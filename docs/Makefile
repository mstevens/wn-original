#!/usr/bin/make -f
#
# source:
#   $Source: /var/cvs/projects/debian/wn/debian/dpkg.src/wn.Makefile.docs.in,v $
#
# revision:
#   @(#) $Id: wn.Makefile.docs.in,v 1.1 1999/02/02 03:36:18 jplejacq Exp $
#
# copyright:
#   Copyright (C) 1999 Jean Pierre LeJacq <jplejacq@quoininc.com>
#
#   Distributed under the GNU GENERAL PUBLIC LICENSE.
#
# synopsis:
#   make [all|manual.stamp-pnuts|clean|distclean]
#
# description:
#   Building program for WN documentation.
#
#   Currently this only augments the manual sections with the WN pnuts
#   navigation links and builds the index.cache files.


# variables:
  MANUAL_SEARCH=dosearch.html

  MANUAL_INDEX=docindex.html

  MANUAL_SECTIONS=\
    manual.html\
    overview.html\
    setup.html\
    index_desc.html\
    security.html\
    search.html\
    parse.html\
    field.html\
    range.html\
    access.html\
    tilde.html\
    multi.html\
    utility.html\
    module.html\
    click.html\
    cgi.html\
    support.html\
    appendixA1.html\
    appendixA2.html\
    appendixB.html\
    appendixC.html\
    appendixD.html\
    appendixE.html\
    appendixF.html\
    configmacros.html\
    howindex.html\
    colophone.html\
    docindex.html


# rules:
  all:\
	  manual.stamp-pnuts\
	  index.cache\
	  authentication/index.cache\
	  examples/index.cache\
	  images/index.cache

  manual.stamp-pnuts: manual.pnuts $(MANUAL_SECTIONS)
	chmod a+x ../bin/wnpnuts
	../bin/wnpnuts -s "$(MANUAL_SEARCH)" -i "$(MANUAL_INDEX)" "${<}"
	@touch "${@}"


  index.cache: index.wn
	@echo "Warning: Making documents in docs/ directory accessible via WN server"
	../wndex/wndex -d .

  authentication/index.cache: authentication/index.wn
	@echo "Skipping document setup in authentication/ directory"
	#../wndex/wndex -d authentication

  examples/index.cache: examples/index.wn
	@echo "Skipping document setup in examples/ directory"
	#../wndex/wndex -d examples

  images/index.cache: images/index.wn
	@echo "Warning: Making files in docs/images directory accessible via WN server"
	../wndex/wndex -d images


  clean:
	$(RM) manual.stamp-pnuts
	$(RM) *~ authentication/*~ examples/*~  examples/roam/*~ \
	examples/roam/*/*~ images/*~

  distclean: clean
	$(RM) index.cache authentication/index.cache examples/index.cache
	$(RM) roam/index.cache images/index.cache


  .PHONY: clean distclean
