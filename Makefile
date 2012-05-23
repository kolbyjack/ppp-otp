PROJECT := otp
SRC := src/$(PROJECT).c
TARGET := lib/$(PROJECT).so
CFLAGS := -fPIC -O2 -fomit-frame-pointer -Wall -Werror -pipe -D__STDC_FORMAT_MACROS
#CFLAGS += -g -DDEBUG -O0
LDFLAGS := -lcrypto
CC := gcc

BUILD := .build
OBJ := $(SRC:%.c=$(BUILD)/%.o)

all $(PROJECT): $(TARGET)

$(shell mkdir -p $(BUILD))
$(shell $(CC) $(CFLAGS) -MM $(SRC) > $(BUILD)/.depend)
include $(BUILD)/.depend

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(shell dirname $@)
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	@mkdir -p $(shell dirname $@)
	@echo LD $(shell basename $@)
	@$(CC) -shared -o $(TARGET) $(OBJ) $(LDFLAGS)

run: /usr/lib/pppd/2.4.5/otp.so
	@sudo strace /usr/sbin/pptpd -f

install: /usr/lib/pppd/2.4.5/otp.so

/usr/lib/pppd/2.4.5/otp.so: $(TARGET)
	@echo CP $(shell basename $(TARGET))
	@sudo cp $(TARGET) /usr/lib/pppd/2.4.5/

clean:
	@echo RM $(shell basename $(TARGET)) $(BUILD)
	@rm -rf $(TARGET) $(BUILD)

