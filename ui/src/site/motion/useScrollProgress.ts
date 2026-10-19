import { useEffect, type RefObject } from "react";

/**
 * Progress (0..1) of scrolling through a tall section whose content is sticky.
 * 0 when the section top reaches the viewport top, 1 when its bottom reaches
 * the viewport bottom. Calls `onProgress` at most once per animation frame.
 */
export function useScrollProgress(ref: RefObject<HTMLElement | null>, onProgress: (progress: number) => void) {
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    let frame = 0;
    const measure = () => {
      frame = 0;
      const rect = element.getBoundingClientRect();
      const travel = rect.height - window.innerHeight;
      const value = travel > 0 ? -rect.top / travel : rect.top < 0 ? 1 : 0;
      onProgress(Math.min(1, Math.max(0, value)));
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(measure);
    };
    measure();
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
    };
  }, [ref, onProgress]);
}
