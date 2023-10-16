# Makefile
#
# Author: Noah BEAUFILS
# Date: 18-oct-2023

SRC =	bxcopy.c

OBJ = $(SRC:.c=.o)
CC = gcc
RM = rm -f
CFLAGS = -Wall -Wextra -Werror

NAME = bxcopy

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean $(NAME)

.PHONY: all clean fclean re

.SILENT: