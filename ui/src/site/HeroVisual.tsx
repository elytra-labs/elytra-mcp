import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { Pause, Play } from "lucide-react";

/** A failed chunk load reports itself unavailable so the static drawing takes over. */
function Unavailable({ onUnavailable }: { onUnavailable?: () => void }) {
  useEffect(() => onUnavailable?.(), [onUnavailable]);
  return <></>;
}
const FlowField = lazy(() => import("./three/FlowField").catch(() => ({ default: Unavailable })));

/** Static wind-tunnel drawing, used without WebGL or with data saving. */
export function FlowSchematic({ className = "field-fallback" }: { className?: string }) {
  const lines = Array.from({ length: 18 }, (_, i) => 120 + i * 32);
  return (
    <svg className={className} viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <g fill="none" strokeWidth="1">
        {lines.map((y) => {
          const near = Math.max(0, 1 - Math.abs(y - 400) / 230);
          return <path key={y} d={`M-20 ${y} C 500 ${y}, 640 ${y - near * 26}, 840 ${y - near * 18} S 1100 ${y + near * 22}, 1240 ${y + near * 30}`} stroke={near > 0 ? "#e6e6e6" : "#b4b4b4"} strokeOpacity={0.12 + near * 0.18} />;
        })}
        <path d="M-20 430 C 500 430, 720 426, 905 418" stroke="#f0b04f" strokeOpacity=".8" strokeWidth="1.4" />
      </g>
      <path d="M640 400 L960 250 L960 318 L842 400 L960 482 L960 550 Z" fill="#141414" stroke="#e8e8e8" strokeOpacity=".55" />
      <path d="M905 405 L960 400 L960 438 L905 430 Z" fill="#1d1b16" stroke="#f0b04f" strokeOpacity=".85" />
      <circle cx="905" cy="418" r="5" fill="#f0b04f" />
    </svg>
  );
}

/**
 * The wind-tunnel flow field behind a section. `hero` loops with a pause
 * control and a caption anchored to the held call; `ambient` renders one still frame.
 */
export default function HeroVisual({ variant = "hero" }: { variant?: "hero" | "ambient" }) {
  const host = useRef<HTMLDivElement>(null);
  const caption = useRef<HTMLDivElement>(null);
  const [near, setNear] = useState(false);
  const [mode, setMode] = useState<{ webgl: boolean; animate: boolean; density: number } | null>(null);
  const [ready, setReady] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [paused, setPaused] = useState(false);
  const onReady = useCallback(() => setReady(true), []);
  const onUnavailable = useCallback(() => {
    setUnavailable(true);
    setReady(false);
  }, []);
  const onAnchor = useCallback((x: number, y: number) => {
    const el = caption.current;
    if (!el) return;
    el.style.left = `${(x * 100).toFixed(2)}%`;
    el.style.top = `${(y * 100).toFixed(2)}%`;
  }, []);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    const connection = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection;
    const update = () => setMode({ webgl: !connection?.saveData, animate: variant === "hero" && !reduced.matches, density: window.innerWidth < 700 ? 0.5 : variant === "ambient" ? 0.6 : 1 });
    update();
    reduced.addEventListener("change", update);
    return () => reduced.removeEventListener("change", update);
  }, [variant]);

  useEffect(() => {
    if (!host.current) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setNear(true);
          observer.disconnect();
        }
      },
      { rootMargin: "300px" },
    );
    observer.observe(host.current);
    return () => observer.disconnect();
  }, []);

  const live = !!mode?.webgl && !unavailable;
  return (
    <div className={`field-layer ${variant} ${ready && live ? "field-ready" : ""}`} ref={host}>
      <div className="field-visual" aria-hidden="true">
        {/* The canvas fades in once its first frame renders; the static drawing is only for no WebGL, so it never flashes first. */}
        {mode && !live && <FlowSchematic />}
        {near && live && mode && (
          <Suspense fallback={null}>
            <FlowField
              mode={variant === "hero" ? "hero" : "still"}
              animate={mode.animate}
              paused={paused}
              density={mode.density}
              onReady={onReady}
              onUnavailable={onUnavailable}
              onAnchor={variant === "hero" ? onAnchor : undefined}
            />
          </Suspense>
        )}
        {variant === "hero" && (
          <div className="field-caption" ref={caption}>
            <i />
            <span>Held for your decision</span>
          </div>
        )}
      </div>
      {variant === "hero" && ready && live && mode?.animate && (
        <button className="motion-button" aria-label={paused ? "Resume background animation" : "Pause background animation"} onClick={() => setPaused(!paused)}>
          {paused ? <Play size={11} /> : <Pause size={11} />}
          <span>{paused ? "Resume" : "Pause"}</span>
        </button>
      )}
    </div>
  );
}
