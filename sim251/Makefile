# Makefile — MCS-251 standalone interpreter
#
# Build:  make
# Test:   make test   (runs the 25-instruction regression suite via run_tests.py)
#
# Performance note: the default build is -O2 (fast). A separate -O0 debug
# build can be made with `make debug` -> ./mcs251_o0; it is roughly 9x
# slower (~7.7 vs ~68.6 Mcy/s) and exists ONLY for stepping through the
# interpreter with a debugger. All test/regression entry points
# (functional.py, cross_validate.py, sim_keil_validate.py, run_periph.py)
# use the optimized ./mcs251 build; never run long regressions with mcs251_o0.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PYTHON  ?= python
SRCDIR  := src
OBJDIR  := obj
BIN     := mcs251
BIN_DBG := mcs251_o0

.DEFAULT_GOAL := $(BIN)

SRCS := $(SRCDIR)/main.c $(SRCDIR)/mem.c $(SRCDIR)/alu.c \
        $(SRCDIR)/cpu.c $(SRCDIR)/soc.c
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# cpu.c includes decode_impl.inc; list it as a dependency.
$(OBJDIR)/cpu.o: $(SRCDIR)/cpu.c $(SRCDIR)/decode_impl.inc $(SRCDIR)/mcs251.h

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/mcs251.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# Debug-only build (unoptimized, ~9x slower). For interactive debugging
# with a debugger; NOT for regressions or performance runs.
debug: $(SRCS) $(SRCDIR)/mcs251.h $(SRCDIR)/decode_impl.inc | $(OBJDIR)
	$(CC) -O0 -g -Wall -Wextra -std=c99 $(SRCS) -o $(BIN_DBG)

$(OBJDIR):
	mkdir -p $(OBJDIR)

.PHONY: clean test debug
clean:
	rm -rf $(OBJDIR) $(BIN)

# Run the 25-instruction regression suite against the standalone emulator.
test: $(BIN)
	cd .. && cmd.exe //c "scripts\\build_compiler.bat scripts\\c251cc.exe"
	$(PYTHON) ../scripts/c251/c251_sim.py
	$(PYTHON) ../scripts/c251/execute_runner.py --limit 12

# Run the STC32G LED demo (P7 running light) and verify the 8-value cycle.
# Expected P7 values over the run: fe fd fb f7 ef df bf 7f (then wraps).
# Note: /tmp is not writable on Android/Termux, so the log goes to ./tmp/.
stc32g: $(BIN) tests/stc32g_led.hex
	./$(BIN) -bios tests/stc32g_led.hex -D ../tmp/stc32g.log --cycles 120000000 --dump-every 3000000
	@echo "P7 values observed:"; grep -oE 'P7=[0-9A-Fa-f]{2}' ../tmp/stc32g.log | sort -u
	@cnt=$$(grep -oE 'P7=(fe|fd|fb|f7|ef|df|bf|7f)' ../tmp/stc32g.log | sort -u | wc -l); \
	if [ "$$cnt" -ge 8 ]; then echo "OK: running-light cycle complete (8 patterns)"; \
	else echo "FAIL: only $$cnt/8 patterns seen"; exit 1; fi
