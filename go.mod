module asterion-firewall-analysis

go 1.25.0

require github.com/Tarafagat/asterion-plugin-contract v0.0.0-00010101000000-000000000000

require gopkg.in/yaml.v3 v3.0.1 // indirect

// asterion-plugin-contract todavía no está publicado en ningún registry —
// hasta que lo esté, este plugin lo necesita clonado como carpeta hermana
// para compilar (mismo criterio que examples/dummy-provider dentro de ese
// mismo repo). Este plugin usa el SDK (pdk) para el servidor HTTP, pero
// TODAVÍA NO tiene plugin.yaml: eso es la fase siguiente, deliberadamente
// separada de "que la API funcione de verdad" (ver README).
replace github.com/Tarafagat/asterion-plugin-contract => ../asterion-plugin-contract
