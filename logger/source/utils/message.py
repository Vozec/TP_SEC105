class message:
    def __init__(self, content, sender):
        self.content = content
        self.sender = sender

    def __str__(self):
        return f'Message from {self.sender}: {self.content}'

    def __repr__(self):
        return self.__str__()