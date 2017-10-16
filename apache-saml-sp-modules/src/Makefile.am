AUTOMAKE_OPTIONS = foreign
WC=-Wc,"$(CFLAGS)"

#   the default target
all: module

#   compile the DSO file
module: mod_saml_sp.c $(TARGET)
	$(APXS) -c $(LIBS) $(WC) $(APXS_LDFLAGS) mod_saml_sp.c

install-exec-local: module
	$(APXS) -i -a -n saml_sp .libs/mod_saml_sp.so
	$(CP) -avr ErrorDocuments/ $(ErrorDocument)

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST= mod_saml_sp.c