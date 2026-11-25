module example.com/demo

go 1.21

require (
	github.com/adrg/xdg v0.2.1
	github.com/google/uuid v1.6.0
)

// same version as required: still dropped
exclude github.com/adrg/xdg v0.2.1

// different version of a required module: must be kept
exclude github.com/google/uuid v1.5.0
