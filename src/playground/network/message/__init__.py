
import Errors
import StandardMessageSpecifiers
from ProtoBuilder import MessageDefinition
from ProtoBuilder import StructuredData as MessageData

"""
The messages module. Using This module you should be able to easily
create network message handling.

class ProtoDef:

    class ControlData:
        class ControlField:
            BODY = [
                ("type", UINT2, bounds(min=245, max=566)),
                ("data", STRING)
                ]
        BODY = [("controlFields", LIST(ControlField))]
            
    PLAYGROUND_IDENTIFIER = "playground.snielson.init.hi"
    VERSION = "1.0"
    BODY = [
      ("count", UINT4),
      ("messages", LIST(STRING), fixedSize("count")),
      ("controlData", ControlData, OPTIONAL)
    ]

  
msgBuilder["count"].set(3)
msgBuilder["messages"].init() # unnecessary unless an empty list is desired
msgBuilder["messages"].add(3)
msgBuilder["messages"][0].set("blah")
msgBuilder["messages"][1].set("blah2")
msgBuilder["messages"][2].set("blah3")
msgBuilder["controlData"].init()
msgBuilder["controlData"]["controlFields"].add()
msgBuilder["controlData"]["controlFields"][0]["type"].set(1)
msgBuilder["controlData"]["controlFields"][1]["data"].set("ha ha")

buf = msgBuilder.serialize()

msg = deserialize(buf)
"""