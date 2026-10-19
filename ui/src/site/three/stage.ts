import * as THREE from "three";

export interface StageOptions {
  /** Upper bound for devicePixelRatio. */
  maxDpr?: number;
  /** Opaque clear color. Additive effects need an opaque canvas to composite correctly. */
  background?: number;
  /** Continuous animation. When false, frames render only after invalidate(). */
  animate: boolean;
  /** Update and render one frame. `dt` is clamped seconds since the last frame. */
  frame: (renderer: THREE.WebGLRenderer, dt: number, elapsed: number) => void;
  resize: (width: number, height: number) => void;
  /** WebGL is unavailable or the context was lost. */
  lost: () => void;
  /** Called once if sustained frame time is too slow; the stage also drops DPR to 1. */
  degrade?: () => void;
}

export interface Stage {
  renderer: THREE.WebGLRenderer;
  /** Request one frame (used for scroll-driven or reduced-motion rendering). */
  invalidate: () => void;
  dispose: (scene?: THREE.Object3D) => void;
}

/**
 * Shared WebGL lifecycle for the public site illustrations: context creation,
 * DPR cap, resize, offscreen and hidden-tab pause, context loss, adaptive
 * quality, and disposal. Returns null when WebGL2 is unavailable.
 */
export function createStage(host: HTMLElement, options: StageOptions): Stage | null {
  let renderer: THREE.WebGLRenderer;
  try {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("webgl2", { alpha: true, antialias: true, powerPreference: "high-performance" });
    if (!context) return null;
    renderer = new THREE.WebGLRenderer({ canvas, context, alpha: true, antialias: true });
  } catch {
    return null;
  }
  let dpr = Math.min(window.devicePixelRatio || 1, options.maxDpr ?? 1.75);
  renderer.setPixelRatio(dpr);
  renderer.setClearColor(options.background ?? 0x000000, options.background === undefined ? 0 : 1);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  host.appendChild(renderer.domElement);

  let width = 0;
  let height = 0;
  const size = () => {
    const rect = host.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    width = rect.width;
    height = rect.height;
    renderer.setSize(width, height);
    options.resize(width, height);
    invalidate();
  };

  let visible = true;
  let tabVisible = !document.hidden;
  let disposed = false;
  let frame = 0;
  let last = 0;
  let elapsed = 0;
  let dirty = true;
  // Adaptive quality: sample frame times once the scene is warm.
  const samples: number[] = [];
  let degraded = false;

  const loop = (time: number) => {
    frame = 0;
    if (disposed || !visible || !tabVisible || !width) return;
    const raw = last ? (time - last) / 1000 : 0;
    const dt = Math.min(Math.max(raw, 0), 0.05);
    last = time;
    elapsed += dt;
    options.frame(renderer, dt, elapsed);
    dirty = false;
    if (options.animate && !degraded && raw > 0) {
      samples.push(raw * 1000);
      if (samples.length === 120) {
        const median = [...samples.slice(30)].sort((a, b) => a - b)[45];
        if (median > 18) {
          degraded = true;
          dpr = 1;
          renderer.setPixelRatio(dpr);
          renderer.setSize(width, height);
          options.degrade?.();
        }
      }
    }
    if (options.animate || dirty) frame = requestAnimationFrame(loop);
  };
  const start = () => {
    if (!frame && visible && tabVisible && !disposed) {
      last = 0;
      frame = requestAnimationFrame(loop);
    }
  };
  const stop = () => {
    cancelAnimationFrame(frame);
    frame = 0;
  };
  function invalidate() {
    dirty = true;
    start();
  }

  const resize = new ResizeObserver(size);
  resize.observe(host);
  const view = new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    if (visible) start();
    else stop();
  });
  view.observe(host);
  const visibility = () => {
    tabVisible = !document.hidden;
    if (tabVisible) start();
    else stop();
  };
  const contextLost = (event: Event) => {
    event.preventDefault();
    stop();
    options.lost();
  };
  document.addEventListener("visibilitychange", visibility);
  renderer.domElement.addEventListener("webglcontextlost", contextLost);
  size();
  start();

  return {
    renderer,
    invalidate,
    dispose(scene) {
      disposed = true;
      stop();
      resize.disconnect();
      view.disconnect();
      document.removeEventListener("visibilitychange", visibility);
      renderer.domElement.removeEventListener("webglcontextlost", contextLost);
      if (scene) disposeTree(scene);
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}

/** Free every geometry, material, and texture under a scene graph. */
export function disposeTree(root: THREE.Object3D) {
  const geometries = new Set<THREE.BufferGeometry>();
  const materials = new Set<THREE.Material>();
  root.traverse((object) => {
    const mesh = object as THREE.Mesh;
    if (mesh.geometry) geometries.add(mesh.geometry);
    const material = mesh.material;
    if (material) (Array.isArray(material) ? material : [material]).forEach((m) => materials.add(m));
  });
  geometries.forEach((g) => g.dispose());
  materials.forEach((material) => {
    for (const value of Object.values(material)) if (value instanceof THREE.Texture) value.dispose();
    const uniforms = (material as THREE.ShaderMaterial).uniforms;
    if (uniforms) for (const u of Object.values(uniforms)) if (u.value instanceof THREE.Texture) u.value.dispose();
    material.dispose();
  });
}

/** Text drawn into a canvas texture, for labels inside 3D scenes. */
export function labelTexture(
  lines: { text: string; font: string; color: string; y: number; x?: number; align?: CanvasTextAlign }[],
  width: number,
  height: number,
): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d")!;
  for (const line of lines) {
    ctx.font = line.font;
    ctx.fillStyle = line.color;
    ctx.textAlign = line.align ?? "left";
    ctx.textBaseline = "middle";
    ctx.fillText(line.text, line.x ?? 0, line.y);
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  return texture;
}

export const prefersReducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
