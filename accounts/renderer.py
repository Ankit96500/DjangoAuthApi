from rest_framework.renderers import JSONRenderer
import json
class customrenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        charset='utf-8'
        response=''
        if 'ErrorDetail' in str(data):
            print('data',data)
            response=json.dumps({'errors':data})
            print('response::',response)
        else:
            response= json.dumps(data)
            
            return response