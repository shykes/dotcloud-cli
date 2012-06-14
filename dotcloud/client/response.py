import json

class BaseResponse(object):
    def __init__(self, obj=None):
        self.obj = obj

    @classmethod
    def create(cls, res=None, trace_id=None, streaming=False):
        resp = None

        if streaming:
            stream = res.iter_lines()
            first_line = next(stream)
            data = json.loads(first_line)
        else:
            if len(res.text):
                data = json.loads(res.text)
            else:
                data = None
        if streaming:
            resp = StreamResponse(obj=data['object'], stream=stream)
        elif data and 'object' in data:
            resp = ItemResponse(obj=data['object'])
        elif data and 'objects' in data:
            resp = ListResponse(obj=data['objects'])
        else:
            resp = NoItemResponse(obj=None)
        resp.trace_id = trace_id
        resp.res = res
        resp.data = data
        return resp

    def find_link(self, rel):
        for link in self.data.get('links', []):
            if link.get('rel') == rel:
                return link
        return None

class ListResponse(BaseResponse):
    @property
    def items(self):
        return self.obj

    @property
    def item(self):
        return self.obj[0]

class ItemResponse(BaseResponse):
    @property
    def items(self):
        return [self.obj]

    @property
    def item(self):
        return self.obj

class NoItemResponse(BaseResponse):
    @property
    def items(self):
        return None

    @property
    def item(self):
        return None

class StreamResponse(BaseResponse):
    def __init__(self, obj, stream):
        BaseResponse.__init__(self, obj)
        self._stream = stream

    @property
    def items(self):
        def stream():
            for line in self._stream:
                yield json.loads(line)['object']
        return stream()

    @property
    def item(self):
        return self.obj
