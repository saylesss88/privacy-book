document.addEventListener("DOMContentLoaded", () => {
  const endpoint = window.NIX_REPL_ENDPOINT || "https://your-nix-eval/eval";

  document.querySelectorAll(".nix-repl-block").forEach(block => {
    const btn = block.querySelector(".nix-repl-run");
    const codeEl = block.querySelector("code");
    const out = block.querySelector(".nix-repl-output");
    const status = block.querySelector(".nix-repl-status");

    if (!btn || !codeEl || !out) return;

    btn.addEventListener("click", async () => {
      const code = codeEl.textContent;
      block.classList.add("running");
      status.textContent = "Running…";
      out.textContent = "";

      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        });
        const data = await res.json();
        if (data.error) {
          block.classList.add("error");
          out.textContent = data.error;
          status.textContent = "Error";
        } else {
          block.classList.remove("error");
          out.textContent = data.stdout || "";
          status.textContent = "Done";
        }
      } catch (e) {
        block.classList.add("error");
        out.textContent = String(e);
        status.textContent = "Network error";
      } finally {
        block.classList.remove("running");
      }
    });
  });
});
