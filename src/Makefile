LDLIBS=-lpcap

all: airodump

airodump:
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm *.o airodump
