NAME	= ft_nmap
CC		= gcc
CFLAGS	= -Wall -Wextra -Werror -Iincludes
LDFLAGS	= -lpcap -lpthread

SRCS	= srcs/main.c srcs/parse_args.c 	srcs/packet.c srcs/capture.c srcs/scan.c srcs/threads.c
OBJS	= $(SRCS:.c=.o)
HEADERS	= includes/ft_nmap.h includes/packet.h includes/scan.h includes/threads.h

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# unit tests (no root needed)
test_packet: srcs/packet.o srcs/parse_args.o tests/test_packet.c
	$(CC) $(CFLAGS) tests/test_packet.c srcs/packet.o srcs/parse_args.o -o tests/test_packet
	./tests/test_packet

test_reply: srcs/capture.o srcs/scan.o srcs/packet.o tests/test_reply.c
	$(CC) $(CFLAGS) tests/test_reply.c srcs/capture.o srcs/scan.o srcs/packet.o -o tests/test_reply $(LDFLAGS)
	./tests/test_reply

# live integration test on loopback (needs root)
test_live: $(NAME)
	sudo bash tests/test_live.sh

# everything that does not need root
test: test_packet test_reply
	bash tests/test_parse.sh

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME) tests/test_packet tests/test_reply

re: fclean all

.PHONY: all clean fclean re test_packet test_reply test_live test
