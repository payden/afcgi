afcgi: $(SAPI_AFCGI_PATH)

$(SAPI_AFCGI_PATH): $(PHP_GLOBAL_OBJS) $(PHP_BINARY_OBJS) $(PHP_AFCGI_OBJS)
	$(BUILD_AFCGI)

install-afcgi: $(SAPI_AFCGI_PATH)
	@echo "Installing PHP AFCGI binary:        $(INSTALL_ROOT)$(bindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	@$(INSTALL) -m 0755 $(SAPI_AFCGI_PATH) $(INSTALL_ROOT)$(bindir)/$(program_prefix)php$(program_suffix)$(EXEEXT)
	@echo "Installing PHP AFCGI man page:      $(INSTALL_ROOT)$(mandir)/man1/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(mandir)/man1
	@$(INSTALL_DATA) sapi/afcgi/php.1 $(INSTALL_ROOT)$(mandir)/man1/$(program_prefix)php$(program_suffix).1

