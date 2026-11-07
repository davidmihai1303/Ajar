// Animated Ajar mascot. Purely visual: the state comes from the score (see lib/scan.ts).
import { useEffect, useRef, useState } from "react";
import "../styles/ajar.css";

export type AjarState = "shut" | "ajar" | "wide" | "locked";

const STROKE = "#2B1B10";

export default function AjarMascot({ state, label }: { state: AjarState; label: string }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [reacting, setReacting] = useState(false);
  const previous = useRef(state);

  // Small "pop" whenever the emotion changes.
  useEffect(() => {
    if (previous.current === state) return;
    previous.current = state;
    setReacting(false);
    const start = window.setTimeout(() => setReacting(true), 10);
    const end = window.setTimeout(() => setReacting(false), 500);
    return () => {
      window.clearTimeout(start);
      window.clearTimeout(end);
    };
  }, [state]);

  // Irregular blinking.
  useEffect(() => {
    let timer = 0;
    const blink = () => {
      svgRef.current?.querySelectorAll(".eye").forEach((eye) => {
        eye.classList.remove("blink");
        void (eye as SVGGElement).getBBox();
        eye.classList.add("blink");
      });
      timer = window.setTimeout(blink, 2500 + Math.random() * 3500);
    };
    timer = window.setTimeout(blink, 1800);
    return () => window.clearTimeout(timer);
  }, []);

  // Pupils follow the pointer (not when terrified: then they stare).
  useEffect(() => {
    const onMove = (event: PointerEvent) => {
      const svg = svgRef.current;
      const matrix = svg?.getScreenCTM();
      if (!svg || !matrix) return;
      const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
      svg.querySelectorAll<SVGGElement>(".pupil").forEach((pupil) => {
        if (state === "wide") {
          pupil.style.transform = "";
          return;
        }
        const cx = Number(pupil.dataset.cx);
        const cy = Number(pupil.dataset.cy);
        const dx = point.x - cx;
        const dy = point.y - cy;
        const distance = Math.hypot(dx, dy) || 1;
        const reach = Math.min(3.5, distance / 20);
        pupil.style.transform = `translate(${(dx / distance) * reach}px, ${(dy / distance) * reach}px)`;
      });
    };
    document.addEventListener("pointermove", onMove);
    return () => document.removeEventListener("pointermove", onMove);
  }, [state]);

  return (
    <div className={`ajar${reacting ? " reacting" : ""}`} data-state={state}>
      <svg ref={svgRef} viewBox="36 22 212 206" role="img" aria-label={label}>
        <rect x="80" y="214" width="140" height="10" rx="5" fill="#4A2E1A" />
        <rect x="90" y="30" width="120" height="190" rx="8" fill="#5A3A22" />
        <rect x="98" y="38" width="104" height="176" rx="4" fill="#1F1F26" />
        <g className="wind" fill="none" stroke="#9FB4C7" strokeWidth="3" strokeLinecap="round">
          <path d="M108 96 q22 -9 44 0 t42 0" />
          <path d="M104 126 q24 -9 48 0 t44 0" />
          <path d="M110 156 q22 -9 44 0 t40 0" />
        </g>
        <g className="door-swing">
          <g className="door-sway">
            <rect x="98" y="38" width="104" height="176" rx="5" fill="#B07A45" />
            <rect x="98" y="38" width="6" height="176" fill="#9A6838" />
            <rect x="112" y="152" width="76" height="48" rx="3" fill="none" stroke="#8A5A30" strokeWidth="2" />
            <circle cx="188" cy="132" r="5.5" fill="#E0B23A" />
            <g className="react">
              <g className="face">
                <g className="st s-locked">
                  <ellipse cx="116" cy="102" rx="8" ry="4.5" fill="#F29BB0" />
                  <ellipse cx="184" cy="102" rx="8" ry="4.5" fill="#F29BB0" />
                </g>
                <g className="st s-shut s-ajar s-wide">
                  <g className="eye">
                    <g className="eye-size">
                      <circle cx="130" cy="84" r="11" fill="#FFFFFF" />
                      <g className="pupil" data-cx="130" data-cy="84">
                        <circle className="pupil-dot" cx="131" cy="85" r="5.5" fill={STROKE} />
                      </g>
                    </g>
                  </g>
                  <g className="eye">
                    <g className="eye-size">
                      <circle cx="170" cy="84" r="11" fill="#FFFFFF" />
                      <g className="pupil" data-cx="170" data-cy="84">
                        <circle className="pupil-dot" cx="171" cy="85" r="5.5" fill={STROKE} />
                      </g>
                    </g>
                  </g>
                </g>
                <g className="st s-locked" fill="none" stroke={STROKE} strokeWidth="3" strokeLinecap="round">
                  <path d="M120 88 Q130 76 140 88" />
                  <path d="M160 88 Q170 76 180 88" />
                </g>
                <g fill="none" stroke={STROKE} strokeWidth="3" strokeLinecap="round">
                  <g className="st s-ajar">
                    <path d="M117 72 Q129 71 139 63" />
                    <path d="M161 63 Q171 71 183 72" />
                  </g>
                  <g className="st s-wide">
                    <path d="M114 62 L140 51" />
                    <path d="M160 51 L186 62" />
                  </g>
                </g>
                <path className="st s-shut" d="M138 106 Q150 115 162 106" fill="none" stroke={STROKE} strokeWidth="3" strokeLinecap="round" />
                <path className="st s-ajar wobble" d="M137 111 Q143.5 105 150 111 Q156.5 117 163 111" fill="none" stroke={STROKE} strokeWidth="3" strokeLinecap="round" />
                <g className="st s-wide">
                  <path d="M136 106 Q150 99 164 106 L161 128 Q150 135 139 128 Z" fill={STROKE} />
                  <path d="M139 106 Q150 101 161 106 L160.5 109 Q150 105 139.5 109 Z" fill="#FFFFFF" />
                  <ellipse cx="150" cy="127" rx="7" ry="3.5" fill="#C9555E" />
                </g>
                <path className="st s-locked" d="M134 102 Q150 126 166 102 Z" fill={STROKE} />
                <path className="st s-ajar drop" d="M190 56 C190 56 196 64 196 67 A6 6 0 0 1 184 67 C184 64 190 56 190 56 Z" fill="#8EC5F0" />
                <g className="st s-wide" fill="#8EC5F0">
                  <path className="drop" d="M192 54 C192 54 198 62 198 65 A6 6 0 0 1 186 65 C186 62 192 54 192 54 Z" />
                  <path className="drop b" d="M108 56 C108 56 113 63 113 66 A5 5 0 0 1 103 66 C103 63 108 56 108 56 Z" />
                </g>
              </g>
            </g>
          </g>
        </g>
        <g className="lock">
          <path d="M181 131 v-7 a7.5 7.5 0 0 1 15 0 v7" fill="none" stroke="#C9971F" strokeWidth="3.5" />
          <rect x="177" y="129" width="23" height="19" rx="3" fill="#E0B23A" />
          <circle cx="188.5" cy="137" r="2.4" fill="#5A3A22" />
          <rect x="187.4" y="137" width="2.2" height="6" fill="#5A3A22" />
        </g>
        <g className="st s-locked" stroke="#E0B23A" strokeWidth="3" strokeLinecap="round">
          <path className="sparkle" d="M232 44 v14 M225 51 h14" />
          <path className="sparkle b" d="M58 62 v10 M53 67 h10" />
          <path className="sparkle" d="M238 120 v8 M234 124 h8" />
        </g>
      </svg>
    </div>
  );
}
