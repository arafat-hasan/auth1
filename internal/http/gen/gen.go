package gen

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../api/openapi.yaml
//go:generate go run ./internal/routegen -spec ../../../api/openapi.yaml -routes routes_gen.go -stub stub_gen.go
