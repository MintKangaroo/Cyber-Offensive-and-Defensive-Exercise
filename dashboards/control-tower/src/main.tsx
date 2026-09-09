import React from "react";
import ReactDOM from "react-dom/client";
import { ErrorBoundary } from "@cyber-range/command-system";
import "@cyber-range/command-system/tokens.css";
import "@cyber-range/command-system/styles.css";
import "./styles.css";
import App from "./App";
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
