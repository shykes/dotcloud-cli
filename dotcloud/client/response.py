class BaseResponse(object):
    def __init__(self, obj=None):
        self.obj = obj

    @classmethod
    def create(cls, res=None, data=None, trace_id=None):
        resp = None
        if data and 'object' in data:
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
