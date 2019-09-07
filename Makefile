OPENRESTY_PREFIX=/usr/local/openresty

#LUA_VERSION := 5.1
#PREFIX ?=          /usr/local
#LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(OPENRESTY_PREFIX)/lualib
INSTALL ?= install

.PHONY: all test install

all: ;

install: all
	$(INSTALL) -d $(LUA_LIB_DIR)/resty/kong/
	$(INSTALL) -m 664 lualib/resty/kong/*.lua $(LUA_LIB_DIR)/resty/kong/
