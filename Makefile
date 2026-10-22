NAME	= ft_nmap
CC		= gcc
CFLAGS	= -Wall -Wextra -Werror -Iincludes -pthread
LDFLAGS	= -lpcap -pthread

SRCS	= srcs/main.c srcs/parse_args.c 	srcs/packet.c srcs/capture.c srcs/scan.c srcs/threads.c
OBJDIR	= objs
OBJS	= $(SRCS:srcs/%.c=$(OBJDIR)/%.o)
LEGACY_OBJS	= $(SRCS:.c=.o)
HEADERS	= includes/ft_nmap.h includes/packet.h includes/scan.h includes/threads.h

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)


$(OBJDIR)/%.o: srcs/%.c $(HEADERS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# unit tests (no root needed)
test_packet: $(OBJDIR)/packet.o $(OBJDIR)/parse_args.o tests/test_packet.c
	$(CC) $(CFLAGS) tests/test_packet.c $(OBJDIR)/packet.o $(OBJDIR)/parse_args.o -o tests/test_packet
	./tests/test_packet

test_reply: $(OBJDIR)/capture.o $(OBJDIR)/scan.o $(OBJDIR)/packet.o tests/test_reply.c
	$(CC) $(CFLAGS) tests/test_reply.c $(OBJDIR)/capture.o $(OBJDIR)/scan.o $(OBJDIR)/packet.o -o tests/test_reply $(LDFLAGS)
	./tests/test_reply

test_edge: $(NAME)
	bash tests/test_edge.sh

# live integration test on loopback (needs root)
test_live: $(NAME)
	sudo bash tests/test_live.sh

# everything that does not need root
test: $(NAME) test_packet test_reply test_edge
	bash tests/test_parse.sh

clean:
	rm -rf $(OBJDIR)
	rm -f $(LEGACY_OBJS)

fclean: clean
	rm -f $(NAME) tests/test_packet tests/test_reply

re: fclean all

.PHONY: all clean fclean re test_packet test_reply test_edge test_live test
