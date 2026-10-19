import { useEffect } from "react";
import Lenis from "lenis";
import "lenis/dist/lenis.css";

let active: Lenis | null = null;

/** Scroll to an element through Lenis when it is running, natively otherwise. */
export function scrollToElement(target: HTMLElement | null, offset = -84) {
  if (active) {
    if (target) active.scrollTo(target, { offset });
    else active.scrollTo(0, { immediate: true });
    return;
  }
  if (target) target.scrollIntoView({ behavior: "smooth" });
  else window.scrollTo({ top: 0, left: 0 });
}

/**
 * Inertial wheel scrolling for the public site. Disabled for reduced motion
 * and for touch-first devices, which keep native scrolling.
 */
export function SmoothScroll() {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const coarse = window.matchMedia("(pointer: coarse)").matches;
    if (reduced || coarse) return;
    const lenis = new Lenis({ duration: 1.05, wheelMultiplier: 0.95, anchors: { offset: -84 } });
    active = lenis;
    let frame = requestAnimationFrame(function raf(time) {
      lenis.raf(time);
      frame = requestAnimationFrame(raf);
    });
    return () => {
      cancelAnimationFrame(frame);
      lenis.destroy();
      if (active === lenis) active = null;
    };
  }, []);
  return null;
}
