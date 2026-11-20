import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Bundled, not fetched from a font service: the browser makes no third-party request.
import "@fontsource-variable/montserrat";
import { App } from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
