const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

async function build() {
  const distDir = path.join(__dirname, "dist");
  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }

  // Copy public/index.html to dist/index.html
  fs.copyFileSync(
    path.join(__dirname, "public", "index.html"),
    path.join(distDir, "index.html")
  );

  // Bundle JavaScript & CSS using esbuild
  await esbuild.build({
    entryPoints: [path.join(__dirname, "src", "index.js")],
    bundle: true,
    minify: true,
    sourcemap: false,
    target: ["es2020"],
    outfile: path.join(distDir, "bundle.js"),
    loader: {
      ".js": "jsx",
      ".jsx": "jsx",
      ".css": "css",
    },
    define: {
      "process.env.NODE_ENV": '"production"',
    },
  });

  // Bundle CSS
  if (fs.existsSync(path.join(__dirname, "src", "App.css"))) {
    fs.copyFileSync(
      path.join(__dirname, "src", "App.css"),
      path.join(distDir, "bundle.css")
    );
  }

  console.log("Frontend production build completed successfully into dist/");
}

build().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
