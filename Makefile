SHELL = /bin/sh
PRGNAM = captive-portal
MODORDER = 100-
VERSION = $(shell git rev-parse --short HEAD)
DESTDIR?=$(PKGBUILDDIR)/$(PRGNAM)
## Variables that should be inherited from the parent Makefile or the environment
# MODULEDIR - the directory where finished modules should but stored
# ISOROOT - The unpacked Porteus iso
# ARCH - from the build environment
# BYZBUILD - Byzantium build version
# MODEXT - module extension (should be '.xzm')
##

# dirs used with root overlay
ROOTOVERLAY_DIRS = opt srv

# output module file path
MODULEPATH = $(MODULEDIR)/$(MODORDER)$(PRGNAM)$(VERSION)-$(ARCH)-$(BYZBUILD).$(MODEXT)

# get specific file names so we can remove only what we put in
FILES = $(shell find opt -type f | sed 's/\.\//,/' )
FILES += $(shell find srv -type f | sed 's/\.\//,/' )

# high level targets
.PHONY : build monolithic module install clean dist-clean

build :
	@echo 'build is a noop in this Makefile'

$(ROOTOVERLAY_DIRS) :
	$(INSTALL_DIR) $@ $(DESTDIR)

monolithic : $(ROOTOVERLAY_DIRS)

$(MODULEPATH) : $(ROOTOVERLAY_DIRS)
	dir2xzm $(DESTDIR) $(MODULEPATH)

module : $(MODULEPATH)
	@echo $(MODULEPATH)

clean :
	# Do *not* remove $(DESTDIR)! If the build is for a monolithic module that will remove everything from every build.
	$(CLEAN) $(DESTDIR)/{$(FILES)}

dist-clean : clean
	$(CLEAN) $(MODULEPATH)
