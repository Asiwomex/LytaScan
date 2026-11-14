import { ImageResponse } from "next/og";

export const alt = "LytaScan. Read-only AWS posture scanner.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const NIGHT = "#0b172b";
const BLUE = "#a9cbff";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-start",
          padding: 86,
          background: NIGHT,
          color: "#eef2f8",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", width: 880 }}>
          <div style={{ fontSize: 36, color: BLUE, fontWeight: 600 }}>LytaScan</div>
          <div
            style={{
              marginTop: 24,
              fontSize: 116,
              fontWeight: 600,
              lineHeight: 1.04,
              letterSpacing: -6,
              display: "flex",
              flexDirection: "column",
            }}
          >
            <span>Find the cracks</span>
            <span>in your AWS.</span>
          </div>
          <div style={{ marginTop: 30, fontSize: 32, color: "#c1d1e8" }}>
            Six pillars · Read-only posture scans
          </div>
        </div>

      </div>
    ),
    size,
  );
}
