import { useEffect, useRef } from "react";
import * as THREE from "three";
import { createStage } from "./stage";

/**
 * Wind-tunnel view of the Elytra control plane. The wing is the logo's delta
 * planform; tool calls are streamlines. Calls that cross the wing leave in
 * a neutral white. One write meets a raised elevon at the trailing edge and stops in
 * amber. Illustrative only: no runtime data.
 */

// Logo planform (16-unit viewBox, y down) mapped to the wing plane: logo y is
// the flow direction (x), logo x is the span (z).
const APEX_X = -2.4;
const CHORD = 4.2;
const SPAN = 2.3;
const toX = (logoY: number) => APEX_X + ((logoY - 2.5) / 11) * CHORD;
const toZ = (logoX: number) => ((logoX - 8) / 6) * SPAN;
const TE_X = toX(13.5);
const NOTCH_X = toX(8.4);
const INNER_Z = Math.abs(toZ(10.8));

const ELEVON = { hinge: TE_X - 0.36, z0: INNER_Z + 0.16, z1: SPAN - 0.28 };
const HELD = { z: (ELEVON.z0 + ELEVON.z1) / 2, y: 0.11 };

const FLOW_START = -8.5;
const FLOW_END = 9;

const smoothstep = (a: number, b: number, v: number) => {
  const t = Math.min(1, Math.max(0, (v - a) / (b - a)));
  return t * t * (3 - 2 * t);
};

/** Leading-edge x at span position z, or null outside the wing. */
function leadingEdge(z: number) {
  const a = Math.abs(z);
  return a < SPAN ? APEX_X + (a / SPAN) * CHORD : null;
}
/** Trailing-edge x at span position z (the notch cuts in near the centerline). */
function trailingEdge(z: number) {
  const a = Math.abs(z);
  return a < INNER_Z ? NOTCH_X + (a / INNER_Z) * (TE_X - NOTCH_X) : TE_X;
}

/** One streamline: rises over the wing, washes down behind it, and rolls into a tip vortex near the tips. */
function streamline(z0: number, y0: number, steps: number): { points: THREE.Vector3[]; over: boolean } {
  const le = leadingEdge(z0);
  const over = le !== null && y0 < 0.6;
  const te = trailingEdge(z0);
  const side = Math.sign(z0) || 1;
  const coreZ = side * (SPAN - 0.12);
  const proximity = Math.exp(-Math.pow(Math.abs(z0) - SPAN, 2) / 0.28) * Math.exp(-y0 * 1.6);
  const points: THREE.Vector3[] = [];
  for (let i = 0; i <= steps; i++) {
    const x = FLOW_START + (i / steps) * (FLOW_END - FLOW_START);
    let y = y0;
    let z = z0;
    if (le !== null) {
      const lift = 0.2 * Math.exp(-y0 * 2.2);
      y += lift * smoothstep(le - 1.4, le + 0.2, x) * (1 - smoothstep(te, te + 3.5, x));
      z *= 1 - 0.035 * smoothstep(le, te, x);
    }
    y -= (over ? 0.32 : 0.1) * smoothstep(TE_X - 0.4, FLOW_END - 1, x);
    // Tip vortex: blend toward a helix around the core behind the trailing edge.
    const w = smoothstep(TE_X - 1.4, TE_X + 0.8, x) * proximity;
    if (w > 0.001) {
      const coreY = 0.12 + 0.04 * Math.max(0, x - TE_X);
      const dz = z0 - coreZ;
      const dy = y0 - 0.12;
      const r0 = Math.max(0.1, Math.hypot(dz, dy));
      const theta0 = Math.atan2(dy, dz);
      const travel = Math.max(0, x - (TE_X - 1.4));
      const theta = theta0 + side * travel * (2.4 / (r0 + 0.25));
      const r = r0 * (1 - 0.3 * smoothstep(TE_X, FLOW_END, x));
      const vz = coreZ + r * Math.cos(theta);
      const vy = coreY + r * Math.sin(theta);
      z = z + (vz - z) * w;
      y = y + (vy - y) * w;
    }
    points.push(new THREE.Vector3(x, y, z));
  }
  return { points, over };
}

const lineVertex = /* glsl */ `
attribute float aT;
attribute float aSeed;
attribute float aOver;
attribute float aLayer;
varying float vT, vSeed, vOver, vLayer, vX;
void main() {
  vT = aT; vSeed = aSeed; vOver = aOver; vLayer = aLayer; vX = position.x;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;
const lineFragment = /* glsl */ `
uniform float uTime, uTrailing;
uniform vec3 uIdle, uPassed, uAmber;
uniform float uHeld;
varying float vT, vSeed, vOver, vLayer, vX;
void main() {
  // Smoke pulses travel downstream along each streamline.
  float dash = fract(vT * 5.0 - uTime * (0.09 + vSeed * 0.05) + vSeed * 7.0);
  float pulse = exp(-dash * 26.0);
  float ends = smoothstep(0.0, 0.16, vT) * (1.0 - smoothstep(0.86, 1.0, vT));
  float depth = mix(1.0, 0.45, vLayer);
  vec3 color = uIdle;
  float alpha = 0.15 + pulse * 0.95;
  if (vOver > 0.5) {
    float passed = smoothstep(uTrailing - 0.2, uTrailing + 0.8, vX);
    color = mix(uIdle, uPassed, passed);
    alpha += passed * 0.1;
  }
  if (uHeld > 0.5) {
    color = uAmber;
    alpha = 0.5 + pulse * 1.0;
    ends = smoothstep(0.0, 0.16, vT);
  }
  gl_FragColor = vec4(color * alpha * ends * depth, 1.0);
}`;

function lineMaterial(held: boolean) {
  return new THREE.ShaderMaterial({
    uniforms: {
      uTime: { value: 0 },
      uTrailing: { value: TE_X },
      uIdle: { value: new THREE.Color(0xb4b4b4) },
      uPassed: { value: new THREE.Color(0xe6e6e6) },
      uAmber: { value: new THREE.Color(0xf0b04f) },
      uHeld: { value: held ? 1 : 0 },
    },
    vertexShader: lineVertex,
    fragmentShader: lineFragment,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
  });
}

/** Merge polylines into one LineSegments geometry with per-vertex flow attributes. */
function segments(lines: { points: THREE.Vector3[]; over: boolean; layer: number; seed: number }[]) {
  const position: number[] = [];
  const t: number[] = [];
  const seed: number[] = [];
  const over: number[] = [];
  const layer: number[] = [];
  for (const line of lines) {
    const n = line.points.length - 1;
    for (let i = 0; i < n; i++) {
      for (const k of [i, i + 1]) {
        const p = line.points[k];
        position.push(p.x, p.y, p.z);
        t.push(k / n);
        seed.push(line.seed);
        over.push(line.over ? 1 : 0);
        layer.push(line.layer);
      }
    }
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.Float32BufferAttribute(position, 3));
  geometry.setAttribute("aT", new THREE.Float32BufferAttribute(t, 1));
  geometry.setAttribute("aSeed", new THREE.Float32BufferAttribute(seed, 1));
  geometry.setAttribute("aOver", new THREE.Float32BufferAttribute(over, 1));
  geometry.setAttribute("aLayer", new THREE.Float32BufferAttribute(layer, 1));
  return geometry;
}

function wingShape() {
  const shape = new THREE.Shape();
  shape.moveTo(toX(2.5), toZ(8));
  shape.lineTo(toX(13.5), toZ(2));
  shape.lineTo(toX(13.5), toZ(5.2));
  shape.lineTo(toX(8.4), toZ(8));
  shape.lineTo(toX(13.5), toZ(10.8));
  shape.lineTo(toX(13.5), toZ(14));
  shape.closePath();
  return shape;
}

function glow(color: number, size: number) {
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 64;
  const ctx = canvas.getContext("2d")!;
  const g = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.25, "rgba(255,255,255,0.35)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, 64, 64);
  const sprite = new THREE.Sprite(
    new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(canvas), color, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, toneMapped: false }),
  );
  sprite.scale.setScalar(size);
  return sprite;
}

export default function FlowField({
  mode,
  animate,
  paused = false,
  density = 1,
  onReady,
  onUnavailable,
  onAnchor,
}: {
  mode: "hero" | "still";
  animate: boolean;
  paused?: boolean;
  density?: number;
  onReady?: () => void;
  onUnavailable?: () => void;
  /** Screen position (0..1 of the host) of the held call, for an HTML label. */
  onAnchor?: (x: number, y: number) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const control = useRef<((paused: boolean) => void) | null>(null);
  const callbacks = useRef({ onReady, onUnavailable, onAnchor });
  callbacks.current = { onReady, onUnavailable, onAnchor };

  useEffect(() => {
    control.current?.(paused);
  }, [paused]);

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 100);
    const rig = new THREE.Group();
    scene.add(rig);

    // Wing: thin machined plate with hairline edges and panel lines.
    const wingGeometry = new THREE.ExtrudeGeometry(wingShape(), { depth: 0.05, bevelEnabled: false }).rotateX(Math.PI / 2).translate(0, 0.025, 0);
    const wing = new THREE.Mesh(wingGeometry, new THREE.MeshStandardMaterial({ color: 0x151515, metalness: 0.55, roughness: 0.42 }));
    rig.add(wing);
    rig.add(new THREE.LineSegments(new THREE.EdgesGeometry(wingGeometry, 30), new THREE.LineBasicMaterial({ color: 0xe8e8e8, transparent: true, opacity: 0.6 })));
    const panel: number[] = [];
    for (let k = 1; k <= 6; k++) {
      const x = APEX_X + (k / 7) * CHORD;
      const half = ((x - APEX_X) / CHORD) * SPAN;
      const notch = x > NOTCH_X ? ((x - NOTCH_X) / (TE_X - NOTCH_X)) * INNER_Z : 0;
      if (notch > 0) panel.push(x, 0.03, -half, x, 0.03, -notch, x, 0.03, notch, x, 0.03, half);
      else panel.push(x, 0.03, -half, x, 0.03, half);
    }
    panel.push(APEX_X + 0.15, 0.03, 0, NOTCH_X - 0.05, 0.03, 0);
    const panelGeometry = new THREE.BufferGeometry();
    panelGeometry.setAttribute("position", new THREE.Float32BufferAttribute(panel, 3));
    rig.add(new THREE.LineSegments(panelGeometry, new THREE.LineBasicMaterial({ color: 0xe8e8e8, transparent: true, opacity: 0.12 })));

    // Raised elevon on the right trailing edge: the control surface holding the write.
    const elevonPivot = new THREE.Group();
    elevonPivot.position.set(ELEVON.hinge, 0.05, (ELEVON.z0 + ELEVON.z1) / 2);
    const elevonGeometry = new THREE.BoxGeometry(TE_X - ELEVON.hinge, 0.035, ELEVON.z1 - ELEVON.z0).translate((TE_X - ELEVON.hinge) / 2, 0, 0);
    const elevon = new THREE.Mesh(elevonGeometry, new THREE.MeshStandardMaterial({ color: 0x1d1b16, metalness: 0.5, roughness: 0.4 }));
    elevon.add(new THREE.LineSegments(new THREE.EdgesGeometry(elevonGeometry), new THREE.LineBasicMaterial({ color: 0xf0b04f, transparent: true, opacity: 0.85, toneMapped: false })));
    elevonPivot.add(elevon);
    elevonPivot.rotation.z = 0.62;
    rig.add(elevonPivot);

    // Streamlines.
    const lines: { points: THREE.Vector3[]; over: boolean; layer: number; seed: number }[] = [];
    const span = Math.max(14, Math.round(30 * density));
    const layers = [0.1, 0.6];
    layers.forEach((y0, layer) => {
      for (let i = 0; i < span; i++) {
        const z0 = -4.4 + ((i + (layer % 2) * 0.5) / (span - 1)) * 8.8;
        // Leave the held call's lane to the amber streamline.
        if (layer === 0 && Math.abs(z0 - HELD.z) < 0.12) continue;
        const { points, over } = streamline(z0, y0, 170);
        lines.push({ points, over, layer: layer / (layers.length - 1), seed: ((i * 37 + layer * 11) % 97) / 97 });
      }
    });
    const flowMaterial = lineMaterial(false);
    rig.add(new THREE.LineSegments(segments(lines), flowMaterial));
    const heldEnd = new THREE.Vector3(ELEVON.hinge + 0.02, HELD.y, HELD.z);
    const heldPoints = streamline(HELD.z, HELD.y, 170).points.filter((p) => p.x < heldEnd.x);
    heldPoints.push(heldEnd);
    const heldMaterial = lineMaterial(true);
    rig.add(new THREE.LineSegments(segments([{ points: heldPoints, over: false, layer: 0, seed: 0.3 }]), heldMaterial));
    const heldGlow = glow(0xf0b04f, 0.9);
    heldGlow.position.copy(heldEnd);
    rig.add(heldGlow);
    const heldGlowMaterial = heldGlow.material as THREE.SpriteMaterial;

    scene.add(new THREE.HemisphereLight(0xf2f2f2, 0x0a0b0c, 1.4));
    const key = new THREE.DirectionalLight(0xffffff, 1.6);
    key.position.set(-3, 6, 4);
    scene.add(key);

    const motion = { running: animate && !paused };
    const pointer = new THREE.Vector2();
    const pointerGoal = new THREE.Vector2();
    let time = mode === "still" ? 7 : 0;
    const view = { target: new THREE.Vector3(), position: new THREE.Vector3() };
    const anchor = new THREE.Vector3();

    const options = {
      maxDpr: 2,
      background: 0x080808,
      animate: motion.running,
      resize(width: number, height: number) {
        camera.aspect = width / height;
        const narrow = width < 860;
        if (mode === "hero" && !narrow) {
          view.position.set(-3.6, 13.5, 11.5);
          view.target.set(-3.3, 0, 1.0);
        } else {
          view.position.set(0, 12.5, 11);
          view.target.set(0, 0, 0.6);
        }
        camera.updateProjectionMatrix();
      },
      frame(renderer: THREE.WebGLRenderer, dt: number) {
        if (motion.running) time += dt;
        pointer.lerp(pointerGoal, Math.min(1, dt * 2.5));
        camera.position.set(view.position.x + pointer.x * 0.5, view.position.y - pointer.y * 0.3, view.position.z);
        camera.lookAt(view.target);
        flowMaterial.uniforms.uTime.value = time;
        heldMaterial.uniforms.uTime.value = time;
        heldGlowMaterial.opacity = 0.7 + (motion.running ? Math.sin(time * 2.2) * 0.2 : 0);
        renderer.render(scene, camera);
        if (callbacks.current.onAnchor) {
          anchor.copy(heldEnd).project(camera);
          callbacks.current.onAnchor((anchor.x + 1) / 2, (1 - anchor.y) / 2);
        }
      },
      lost: () => callbacks.current.onUnavailable?.(),
    };
    const stage = createStage(element, options);
    if (!stage) {
      callbacks.current.onUnavailable?.();
      return;
    }
    stage.renderer.toneMapping = THREE.ACESFilmicToneMapping;

    const onPointer = (event: PointerEvent) => {
      const rect = element.getBoundingClientRect();
      pointerGoal.set(((event.clientX - rect.left) / rect.width) * 2 - 1, ((event.clientY - rect.top) / rect.height) * 2 - 1);
    };
    const onLeave = () => pointerGoal.set(0, 0);
    const target = element.closest("section") ?? element;
    if (motion.running) {
      target.addEventListener("pointermove", onPointer as EventListener);
      target.addEventListener("pointerleave", onLeave);
    }
    control.current = (value) => {
      motion.running = animate && !value;
      options.animate = motion.running;
      stage.invalidate();
    };
    stage.invalidate();
    callbacks.current.onReady?.();
    return () => {
      target.removeEventListener("pointermove", onPointer as EventListener);
      target.removeEventListener("pointerleave", onLeave);
      control.current = null;
      stage.dispose(scene);
    };
  }, [mode, animate, density]);

  return <div className="case-canvas" ref={host} aria-hidden="true" />;
}
