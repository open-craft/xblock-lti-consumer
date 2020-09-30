from rest_framework import serializers
from rest_framework.reverse import reverse

from openedx.core.lib.api.serializers import UsageKeyField

from lti_consumer.models import LtiAgsLineItem, LtiAgsScore


class LtiAgsLineItemSerializer(serializers.ModelSerializer):
    """
    LTI AGS LineItem Serializer.

    This maps out the internally stored LineItemParameters to
    the LTI-AGS API Specification, as shown in the example
    response below:

    {
        "id" : "https://lms.example.com/context/2923/lineitems/1",
        "scoreMaximum" : 60,
        "label" : "Chapter 5 Test",
        "resourceId" : "a-9334df-33",
        "tag" : "grade",
        "resourceLinkId" : "1g3k4dlk49fk"
        "startDateTime": "2018-03-06T20:05:02Z"
        "endDateTime": "2018-04-06T22:05:03Z"
    }

    Note: The platform MUST NOT modify the 'resourceId', 'resourceLinkId' and 'tag' values.

    Reference:
    https://www.imsglobal.org/spec/lti-ags/v2p0#example-application-vnd-ims-lis-v2-lineitem-json-representation
    """
    # Id needs to be overriden and be a URL to the LineItem endpoint
    id = serializers.SerializerMethodField()

    # Mapping from snake_case to camelCase
    resourceId = serializers.CharField(source='resource_id')
    scoreMaximum = serializers.IntegerField(source='score_maximum')
    resourceLinkId = UsageKeyField(required=False, source='resource_link_id')
    startDateTime = serializers.DateTimeField(required=False, source='start_date_time')
    endDateTime = serializers.DateTimeField(required=False, source='end_date_time')

    def get_id(self, obj):
        request = self.context.get('request')
        return reverse(
            'lti_consumer:lti-ags-view-detail',
            kwargs={
                'lti_config_id': obj.lti_configuration.id,
                'pk': obj.pk
            },
            request=request,
        )

    class Meta:
        model = LtiAgsLineItem
        fields = (
            'id',
            'resourceId',
            'scoreMaximum',
            'label',
            'tag',
            'resourceLinkId',
            'startDateTime',
            'endDateTime',
        )


class LtiAgsScoreSerializer(serializers.ModelSerializer):
    """
    LTI AGS LineItemScore Serializer.

    This maps out the internally stored LineItemScoreParameters to
    the LTI-AGS API Specification, as shown in the example
    response below:

    {
      "timestamp": "2017-04-16T18:54:36.736+00:00",
      "scoreGiven" : 83,
      "scoreMaximum" : 100,
      "comment" : "This is exceptional work.",
      "activityProgress" : "Completed",
      "gradingProgress": "FullyGraded",
      "userId" : "5323497"
    }

    Reference:
    https://www.imsglobal.org/spec/lti-ags/v2p0#example-application-vnd-ims-lis-v1-score-json-representation
    """

    timestamp = serializers.DateTimeField()
    scoreGiven = serializers.IntegerField(source='score_given')
    scoreMaximum = serializers.IntegerField(source='score_maximum')
    comment = serializers.CharField()
    activityProgress = serializers.CharField(source='activity_progress')
    gradingProgress = serializers.CharField(source='grading_progress')
    userId = serializers.CharField(source='user_id')

    class Meta:
        model = LtiAgsScore
        fields = (
            'timestamp',
            'scoreGiven',
            'scoreMaximum',
            'comment',
            'activityProgress',
            'gradingProgress',
            'userId',
        )
