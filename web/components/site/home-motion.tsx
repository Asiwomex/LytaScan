"use client";

import { useEffect } from "react";

export function HomeMotion() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.setAttribute("data-home-visible", "");
        observer.unobserve(entry.target);
      }
    }, { threshold: 0.12 });
    for (const item of document.querySelectorAll("[data-home-enter]")) observer.observe(item);
    return () => observer.disconnect();
  }, []);

  return null;
}
