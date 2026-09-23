import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { GlobalTooltipLayer } from "./components/GlobalTooltipLayer";
import { initializeDocumentTheme } from "./components/ThemeToggle";
import "./ui.css";
import "./styles.css";
import "./forge-theme.css";

initializeDocumentTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
    <GlobalTooltipLayer />
  </React.StrictMode>,
);
