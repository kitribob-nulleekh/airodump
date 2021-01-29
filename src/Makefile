LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o radiotaphdr.h
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm *.o airodump
