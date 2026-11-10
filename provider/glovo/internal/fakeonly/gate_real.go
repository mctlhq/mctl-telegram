//go:build glovo_real

package fakeonly

// M1 ships no real provider adapter. Building with the glovo_real tag is a
// deliberate compile error until a reviewed change replaces this stub.
const RealAdapterCompiled = true

var _ = realAdapterIsNotImplementedInThisSlice
