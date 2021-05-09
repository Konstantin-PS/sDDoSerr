COMPILATOR=gcc
SOURCES=sDDoSerr.c minIni.c cmd_parser.c udp_sender.c
DIR=bin/
EXECUTABLE=sDDoSerr
all: sDDoSerr

sDDoSerr: $(SOURCES)
	$(COMPILATOR) $(SOURCES) -o $(DIR)$(EXECUTABLE) -lm

debug: $(SOURCES)
	$(COMPILATOR) $(SOURCES) -o $(DIR)$(EXECUTABLE) -lm -fsanitize=address -g
