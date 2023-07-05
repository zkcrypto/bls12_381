
# Checks two given strings for equality.
eq = $(if $(or $(1),$(2)),$(and $(findstring $(1),$(2)),\
                                $(findstring $(2),$(1))),1)

# Create a release build.
#
# Usage:
#	make release [target=(|web)]

release :
	wasm-pack build ./ --out-dir dist/pkg --release --target $(if $(call eq,$(target),),nodejs,$(target))

# Create a development build (enable debug info, and disable optimizations).
#
# Usage:
#	make build [target=(|web)]

build :
	wasm-pack build ./ --out-dir dist/pkg --dev --target $(if $(call eq,$(target),),nodejs,$(target))

# Install prerequisites.
#
# Usage:
#	make prerequisite

prerequisite :
	cargo install wasm-pack

#
# === .PHONY section
#

.PHONY: \
	release \
	build \
	prerequisite
