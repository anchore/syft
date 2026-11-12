package internal

// MaxSafeTensorsHeaderSize caps a safetensors header's JSON (excluding its
// 8-byte length prefix). Shared by the ai cataloger and the OCI model source so
// dir and OCI scans accept the same headers. Real-world shard headers are well
// under 1 MB.
const MaxSafeTensorsHeaderSize = 8 * 1024 * 1024
