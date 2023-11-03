# SPDX-License-Identifier: LGPL-2.1-or-later

import abc


class XDRReader:
    def __init__(self, fp):
        self.fp = fp
        self.lookahead = ""
        self.lookbehind = ""
        self.line = 1
        self.column = 0

    def _read(self):
        if len(self.lookahead) > 0:
            c = self.lookahead[0:1]
            self.lookahead = self.lookahead[1:]
            return c
        return self.fp.read(1)

    def peek(self, skip=0):
        need = 1 + skip
        if len(self.lookahead) < need:
            self.lookahead = self.lookahead + self.fp.read(need - len(self.lookahead))
        if len(self.lookahead) < need:
            return None

        return self.lookahead[skip : skip + 1]

    def last(self, skip=0):
        if (skip + 1) > len(self.lookbehind):
            return None
        return self.lookbehind[skip]

    def next(self):
        c = self._read()
        line = self.line
        column = self.column
        if c == "\n":
            self.line = self.line + 1
            self.column = 0
        else:
            self.column = self.column + 1
        self.lookbehind = c + self.lookbehind
        if len(self.lookbehind) > 2:
            self.lookbehind = self.lookbehind[0:2]
        return c, line, column


class XDRToken(abc.ABC):
    def __init__(self, line, column, value):
        self.line = line
        self.column = column
        self.value = value

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.line == other.line
            and self.column == other.column
            and self.value == other.value
        )

    @classmethod
    @abc.abstractmethod
    def start(cls, reader):
        pass

    @classmethod
    @abc.abstractmethod
    def end(cls, reader):
        pass

    @classmethod
    def consume(cls, reader):
        c, line, col = reader.next()
        buf = c
        while True:
            if cls.end(reader):
                break
            c, _, _ = reader.next()
            buf = buf + c
        return cls(line, col, buf)

    def __repr__(self):
        return "%s{line=%d,col=%d,value={{{%s}}}}" % (
            self.__class__.__name__,
            self.line,
            self.column,
            self.value,
        )


class XDRTokenComment(XDRToken):
    @classmethod
    def start(cls, reader):
        return reader.peek() == "/" and reader.peek(skip=1) == "*"

    @classmethod
    def end(cls, reader):
        c1 = reader.last(skip=1)
        c2 = reader.last()
        if c1 == "*" and c2 == "/":
            return True

        if reader.peek() is None:
            raise Exception(
                "EOF before closing comment starting at %d:%d"
                % (reader.line, reader.column)
            )


class XDRTokenIdentifier(XDRToken):
    @classmethod
    def start(cls, reader):
        c = reader.peek()
        return c.isalpha()

    @classmethod
    def end(cls, reader):
        c = reader.peek()
        if c is None:
            return True
        return not c.isalnum() and c != "_"


class XDRTokenPunctuation(XDRToken):
    @classmethod
    def start(cls, reader):
        c = reader.peek()
        return c in [";", "=", "{", "}", ",", "[", "]", "<", ">", "*", "(", ")", ":"]

    @classmethod
    def end(cls, reader):
        return True


class XDRTokenConstant(XDRToken):
    @classmethod
    def start(cls, reader):
        c1 = reader.peek()
        c2 = reader.peek(skip=1)
        return c1.isdecimal() or (c1 == "-" and c2 is not None and c2.isdecimal())

    @classmethod
    def end(cls, reader):
        c = reader.peek()
        return (
            not c.isdecimal()
            and not c == "."
            and not c.lower() in ["x", "a", "b", "c", "d", "e", "f"]
        )


class XDRTokenCEscape(XDRToken):
    @classmethod
    def start(cls, reader):
        return reader.column == 0 and reader.peek() == "%"

    @classmethod
    def end(cls, reader):
        return reader.peek() == "\n"


class XDRTokenSpace(XDRToken):
    @classmethod
    def start(cls, reader):
        return reader.peek().isspace()

    @classmethod
    def end(cls, reader):
        c = reader.peek()
        return c is None or not c.isspace()


class XDRLexer:
    def __init__(self, fp):
        self.reader = XDRReader(fp)
        self.lookahead = []

    def _token(self):
        tokenTypes = [
            XDRTokenComment,
            XDRTokenIdentifier,
            XDRTokenCEscape,
            XDRTokenPunctuation,
            XDRTokenConstant,
            XDRTokenSpace,
        ]
        while True:
            if self.reader.peek() is None:
                return None

            for tokenType in tokenTypes:
                if tokenType.start(self.reader):
                    ret = tokenType.consume(self.reader)
                    if type(ret) not in [XDRTokenSpace, XDRTokenComment]:
                        return ret

    def next(self):
        if len(self.lookahead) > 0:
            token = self.lookahead[0]
            self.lookahead = self.lookahead[1:]
            return token
        return self._token()

    def peek(self):
        if len(self.lookahead) == 0:
            token = self._token()
            if token is None:
                return None
            self.lookahead.append(token)
        return self.lookahead[0]
