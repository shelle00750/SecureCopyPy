all:

clean:

install:
	chmod 755 setup.py
	chmod 755 run.sh
	chmod 755 scppy.py
	mkdir -p $(DESTDIR)/opt/scppy/
	mkdir -p $(DESTDIR)/usr/share/doc/scppy/
	mkdir -p $(DESTDIR)/usr/bin/
	cp setup.py $(DESTDIR)/opt/scppy/
	cp LICENSE $(DESTDIR)/opt/scppy/
	cp Makefile $(DESTDIR)/opt/scppy/
	cp README.md $(DESTDIR)/opt/scppy/
	cp README.md $(DESTDIR)/usr/share/doc/scppy/
	cp run.sh $(DESTDIR)/opt/scppy/
	cp run.sh $(DESTDIR)/usr/bin/
	cp scppy.py $(DESTDIR)/opt/scpyp/
