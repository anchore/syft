package cataloging

// ExecutorCPU is the name to use when executing parallel functions which are CPU-intensive, such as
// hashing full files
const ExecutorCPU = "cpu"

// ExecutorFile is the name to use when executing parallel file reading functions, such as cataloging
const ExecutorFile = "file"
