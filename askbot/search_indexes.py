import datetime
from askbot.models.question import Thread
from askbot.models.post import Post
from haystack import indexes, site

__author__ = 'jmadynski'

class ThreadIndex(indexes.SearchIndex):
    text = indexes.CharField(document=True, use_template=True)
    title_auto = indexes.EdgeNgramField(model_attr='title')
    tagnames_auto = indexes.EdgeNgramField(model_attr='tagnames')
    def get_model(self):
        return Thread

    def index_queryset(self):
        """Used when the entire index for model is updated."""
        return self.get_model().objects.all()



class PostIndex(indexes.SearchIndex):
    text = indexes.CharField(document=True, use_template=True)
    text_auto = indexes.EdgeNgramField(model_attr='text')
    def get_model(self):
        return Post

    def index_queryset(self):
        """Used when the entire index for model is updated."""
        return self.get_model().objects.filter(deleted=False)


site.register(Thread, ThreadIndex)
site.register(Post, PostIndex)