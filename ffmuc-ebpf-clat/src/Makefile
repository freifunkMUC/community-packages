# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT ?= build
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= x86
CLAT_CFLAGS ?= $(CFLAGS) -g -Wall
CLAT_LDFLAGS ?= $(LDFLAGS)
CLAT_INCLUDES ?=
CLANG_INCLUDES ?=
APPS ?= clat

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# # Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) \
			$(CLANG_INCLUDES) \
			-c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CLAT_CFLAGS) -I$(OUTPUT) -c $(filter %.c,$^) \
			$(CC_INCLUDES) \
			-o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CLAT_CFLAGS) $^ \
			$(CLAT_LDFLAGS) \
			-lelf -lbpf -lz \
			-o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
