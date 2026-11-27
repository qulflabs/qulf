"use client";

import mermaid from "mermaid";
import { useTheme } from "next-themes";
import { useEffect, useId, useRef } from "react";

interface MermaidProps {
  chart: string;
}

export function Mermaid({ chart }: MermaidProps) {
  const id = useId().replace(/:/g, "");
  const containerRef = useRef<HTMLDivElement>(null);
  const { resolvedTheme } = useTheme();

  useEffect(() => {
    let cancelled = false;

    async function render() {
      const dark = resolvedTheme === "dark";

      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        look: "handDrawn",
        fontFamily: "inherit",

        themeVariables: {
          darkMode: dark,
          background: "transparent",
          fontFamily: "inherit",
          fontSize: "14px",

          // Primary
          primaryColor: dark ? "#1e293b" : "#f1f5f9",
          primaryTextColor: dark ? "#e2e8f0" : "#1e293b",
          primaryBorderColor: dark ? "#475569" : "#cbd5e1",

          // Secondary
          secondaryColor: dark ? "#172554" : "#eff6ff",
          secondaryTextColor: dark ? "#bfdbfe" : "#1e40af",
          secondaryBorderColor: dark ? "#3b82f6" : "#93c5fd",

          // Tertiary
          tertiaryColor: dark ? "#2e1065" : "#f5f3ff",
          tertiaryTextColor: dark ? "#ddd6fe" : "#5b21b6",
          tertiaryBorderColor: dark ? "#8b5cf6" : "#c4b5fd",

          // Connections
          lineColor: dark ? "#64748b" : "#94a3b8",
          textColor: dark ? "#e2e8f0" : "#334155",

          // Clusters
          clusterBkg: dark ? "#111827" : "#f8fafc",
          clusterBorder: dark ? "#334155" : "#e2e8f0",

          // Edge labels
          edgeLabelBackground: dark ? "#111827" : "#ffffff",
        },

        flowchart: {
          curve: "basis",
          nodeSpacing: 45,
          rankSpacing: 55,
          padding: 16,
          htmlLabels: true,
          useMaxWidth: true,
        },
      });

      try {
        const { svg, bindFunctions } = await mermaid.render(
          `mermaid-${id}`,
          chart,
        );

        if (cancelled || !containerRef.current) return;

        containerRef.current.innerHTML = svg;
        bindFunctions?.(containerRef.current);
      } catch (error) {
        if (cancelled || !containerRef.current) return;

        console.error("Mermaid rendering failed:", error);
        containerRef.current.textContent = chart;
      }
    }

    void render();

    return () => {
      cancelled = true;
    };
  }, [chart, id, resolvedTheme]);

  return <div ref={containerRef} className="mermaid-container" />;
}
