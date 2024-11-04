Color Switch
=============

Version supported : 3

.. contents::
   :depth: 2
   :local:
   :backlinks: none


Interview process
*****************

#. :ref:`Color Switch Supported Get <color-switch-supported-get-command>`
#. For each supported Color Component: :ref:`Color Switch Get <color-switch-get-command>`

Command Class Commands
**********************

.. _color-switch-supported-get-command:

Color Switch Supported Get 
---------------------------

Trigger on undefined **reported** value of ``SUPPORTED_COLOR_COMPONENT_MASK``.

Color Switch Supported Report 
------------------------------

Mapping between Report command and attribute store : 

.. list-table:: 
  :header-rows: 1

  * - Z-Wave Command Attribute 
    - Z-Wave Attribute Store
  * - ``Color Component mask 1 | ((Color Component mask 2) << 8)``
    - ``SUPPORTED_COLOR_COMPONENT_MASK``  

.. note:: 
  ``Color Component mask 1``, ``Color Component mask 2`` used for calculating supported ``COLOR_COMPONENT_ID`` 


Color Switch Set
-------------------------------

Trigger on new **desired** value of ``VALUE``. 

Mapping between attribute store and Set command: 

.. list-table:: 
  :header-rows: 1

  * - Z-wave Attribute Store 
    - Attribute State
    - Z-wave Set Field
  * - ``VALUE``
    - Desired or Reported
    - ``Value``
  * - ``DURATION``
    - Desired or Reported
    - ``Duration``
  * - ``COLOR_COMPONENT_ID``
    - Desired or Reported
    - ``Color Component ID``

.. _color-switch-get-command:

Color Switch Get
-------------------------------

Trigger on undefined **reported** value of ``VALUE``.


Color Switch Report
----------------------------------

Mapping between Report command and attribute store :

.. list-table:: 
  :header-rows: 1

  * - Report Field Command 
    - Z-Wave Attribute Store 
  * - ``Color Component ID``
    - ``COLOR_COMPONENT_ID``
  * - ``Current Value``
    - ``VALUE``
  * - ``Duration``
    - ``DURATION``

Color Switch Start Level Change 
--------------------------

Trigger on new **desired** value of ``START_CHANGE``.

Mapping between attribute store and command: 

.. list-table:: 
  :header-rows: 1

  * - Z-wave Attribute Store 
    - Attribute State
    - Z-wave Set Field
  * - ``START_LEVEL``
    - Desired or Reported
    - ``Start Level``
  * - ``UP_DOWN``
    - Desired or Reported
    - ``Up/Down``
  * - ``IGNORE_START_LEVEL``
    - Desired or Reported
    - ``Ignore Start State``
  * - ``COLOR_COMPONENT_ID``
    - Desired or Reported
    - ``Color Component ID``
  * - ``START_LEVEL``
    - Desired or Reported
    - ``Start Level``
  * - ``DURATION``
    - Desired or Reported
    - ``Duration``



Color Switch Stop Level Change 
--------------------------

Trigger on new **desired** value of ``STOP_CHANGE``.

Mapping between attribute store and command: 

.. list-table:: 
  :header-rows: 1

  * - Z-wave Attribute Store 
    - Attribute State
    - Z-wave Set Field
  * - ``COLOR_COMPONENT_ID``
    - Desired or Reported
    - ``Color Component ID``

.. note:: 
    The structure of the attribute store is : 

    .. code:: text
        
        |__ SUPPORTED_COLOR_COMPONENT_MASK
        |__ STATE
            |__ COLOR_COMPONENT_ID
            |    |__ VALUE
            |    |__ START_CHANGE
            |    |__ STOP_CHANGE
            |__ DURATION
            |__ UP_DOWN
            |__ IGNORE_START_LEVEL
            |__ START_LEVEL


Unify Clusters
**************

UAM files
---------

.. list-table:: 
  :header-rows: 1

  * - UAM File
    - Cluster
    - Comments
  * - ``SwitchColor.uam``
    - ``Unify_SwitchColor.xml``
    - Mapping between Color Switch command class and Color Switch cluster

Bindings
--------

.. list-table:: 
  :header-rows: 1

  * - Z-Wave Attribute Store
    - Cluster attribute
    - Comments
  * - ``VALUE``
    - UnifySwitchColor WarmWhite
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x00)
  * - ``VALUE``
    - UnifySwitchColor ColdWhite
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x01)
  * - ``VALUE``
    - UnifySwitchColor Red
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x02)
  * - ``VALUE``
    - UnifySwitchColor Green
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x03)
  * - ``VALUE``
    - UnifySwitchColor Blue
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x04)
  * - ``VALUE``
    - UnifySwitchColor Amber
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x05)
  * - ``VALUE``
    - UnifySwitchColor Cyan
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x06)
  * - ``VALUE``
    - UnifySwitchColor Purple
    - Z-Wave <-> Cluster (If ``COMPONENT_ID`` = 0x07)


Command actions
---------------

.. list-table:: 
  :widths: 20 50 30
  :header-rows: 1

  * - Action
    - MQTT Topic
    - Comments
  * - End user performs set the color
    - ``ucl/by-unid/<UNID>/<EP>/UnifySwitchColor/Commands/SetColor {"ColorComponentId" : 4, "Value" : 100, "Duration" : 0}`` 
    - See ``ColorComponentId`` values in Bindings table
  * - End user performs start/stop enhancing a color component
    - ``ucl/by-unid/<UNID>/<EP>/UnifySwitchColor/Commands/StartStopChange {"StartStop" : true, "UpDown" : false, "IgnorStartLevel" : true, "ColorComponentId" : 2, "StartLevel" : 50, "Duration" : 10}`` 
    - ``StartStop`` = ``true`` for Start level change, = ``false`` for Stop level change; ``UpDown`` = ``true`` for decreasing, = ``false`` for increasing