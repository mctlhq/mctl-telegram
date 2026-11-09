//go:build !glovo_real

package fakeonly

// RealAdapterCompiled reports whether a real provider adapter is part of this
// binary. In the default build the only adapter is internal/fakestore.
const RealAdapterCompiled = false
