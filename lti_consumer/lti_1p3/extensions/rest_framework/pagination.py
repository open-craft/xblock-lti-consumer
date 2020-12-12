"""
Custom Pagination Implementation
"""
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class LinkHeaderPagination(PageNumberPagination):
    """
    Pagination via link header.
    """

    def get_paginated_response(self, data):
        """
        Add next and prev page urls to Link header if exists.
        """
        next_page = self.get_next_link()
        prev_page = self.get_previous_link()

        links = [
            (next_page, 'next'),
            (prev_page, 'prev'),
        ]

        header_links = ['<{}>; rel="{}"'.format(link, rel) for link, rel in links if link]

        headers = {'Link': ', '.join(header_links)} if len(header_links) > 0 else {}

        return Response(data, headers=headers)
