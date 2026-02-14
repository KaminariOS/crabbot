import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const schemaPath = path.resolve(packageRoot, "../../../../schemas/openapi.yaml");
const outputPath = path.resolve(packageRoot, "src/generated.ts");

const ast = await openapiTS(new URL(`file://${schemaPath}`));
const content = astToString(ast);
const header = "// Generated from schemas/openapi.yaml. Do not edit manually.\n\n";

await fs.writeFile(outputPath, `${header}${content}`);
console.log(`Generated ${path.relative(packageRoot, outputPath)}`);
