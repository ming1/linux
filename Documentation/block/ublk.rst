.. SPDX-License-Identifier: GPL-2.0

===========================================
Userspace block device driver (ublk driver)
===========================================

Overview
========

ublk is a generic framework for implementing block device logic from userspace.
The motivation behind it is that moving virtual block drivers into userspace,
such as loop, nbd and similar can be very helpful. It can help to implement
new virtual block device such as ublk-qcow2 (there are several attempts of
implementing qcow2 driver in kernel).

Userspace block devices are attractive because:

- They can be written many programming languages.
- They can use libraries that are not available in the kernel.
- They can be debugged with tools familiar to application developers.
- Crashes do not kernel panic the machine.
- Bugs are likely to have a lower security impact than bugs in kernel
  code.
- They can be installed and updated independently of the kernel.
- They can be used to simulate block device easily with user specified
  parameters/setting for test/debug purpose

ublk block device (``/dev/ublkb*``) is added by ublk driver. Any IO request
on the device will be forwarded to ublk userspace program. For convenience,
in this document, ``ublk server`` refers to generic ublk userspace
program. ``ublksrv`` [#userspace]_ is one of such implementation. It
provides ``libublksrv`` [#userspace_lib]_ library for developing specific
user block device conveniently, while also generic type block device is
included, such as loop and null. Richard W.M. Jones wrote userspace nbd device
``nbdublk`` [#userspace_nbdublk]_  based on ``libublksrv`` [#userspace_lib]_.

After the IO is handled by userspace, the result is committed back to the
driver, thus completing the request cycle. This way, any specific IO handling
logic is totally done by userspace, such as loop's IO handling, NBD's IO
communication, or qcow2's IO mapping.

``/dev/ublkb*`` is driven by blk-mq request-based driver. Each request is
assigned by one queue wide unique tag. ublk server assigns unique tag to each
IO too, which is 1:1 mapped with IO of ``/dev/ublkb*``.

Both the IO request forward and IO handling result committing are done via
``io_uring`` passthrough command; that is why ublk is also one io_uring based
block driver. It has been observed that using io_uring passthrough command can
give better IOPS than block IO; which is why ublk is one of high performance
implementation of userspace block device: not only IO request communication is
done by io_uring, but also the preferred IO handling in ublk server is io_uring
based approach too.

ublk provides control interface to set/get ublk block device parameters.
The interface is extendable and kabi compatible: basically any ublk request
queue's parameter or ublk generic feature parameters can be set/get via the
interface. Thus, ublk is generic userspace block device framework.
For example, it is easy to setup a ublk device with specified block
parameters from userspace.

Using ublk
==========

ublk requires userspace ublk server to handle real block device logic.

Below is example of using ``ublksrv`` to provide ublk-based loop device.

- add a device::

     ublk add -t loop -f ublk-loop.img

- format with xfs, then use it::

     mkfs.xfs /dev/ublkb0
     mount /dev/ublkb0 /mnt
     # do anything. all IOs are handled by io_uring
     ...
     umount /mnt

- list the devices with their info::

     ublk list

- delete the device::

     ublk del -a
     ublk del -n $ublk_dev_id

See usage details in README of ``ublksrv`` [#userspace_readme]_.

Design
======

Control plane
-------------

ublk driver provides global misc device node (``/dev/ublk-control``) for
managing and controlling ublk devices with help of several control commands:

- ``UBLK_CMD_ADD_DEV``

  Add a ublk char device (``/dev/ublkc*``) which is talked with ublk server
  WRT IO command communication. Basic device info is sent together with this
  command. It sets UAPI structure of ``ublksrv_ctrl_dev_info``,
  such as ``nr_hw_queues``, ``queue_depth``, and max IO request buffer size,
  for which the info is negotiated with the driver and sent back to the server.
  When this command is completed, the basic device info is immutable.

- ``UBLK_CMD_SET_PARAMS`` / ``UBLK_CMD_GET_PARAMS``

  Set or get parameters of the device, which can be either generic feature
  related, or request queue limit related, but can't be IO logic specific,
  because the driver does not handle any IO logic. This command has to be
  sent before sending ``UBLK_CMD_START_DEV``.

- ``UBLK_CMD_START_DEV``

  After the server prepares userspace resources (such as creating per-queue
  pthread & io_uring for handling ublk IO), this command is sent to the
  driver for allocating & exposing ``/dev/ublkb*``. Parameters set via
  ``UBLK_CMD_SET_PARAMS`` are applied for creating the device.

- ``UBLK_CMD_STOP_DEV``

  Halt IO on ``/dev/ublkb*`` and remove the device. When this command returns,
  ublk server will release resources (such as destroying per-queue pthread &
  io_uring).

- ``UBLK_CMD_DEL_DEV``

  Remove ``/dev/ublkc*``. When this command returns, the allocated ublk device
  number can be reused.

- ``UBLK_CMD_GET_QUEUE_AFFINITY``

  When ``/dev/ublkc`` is added, the driver creates block layer tagset, so
  that each queue's affinity info is available. The server sends
  ``UBLK_CMD_GET_QUEUE_AFFINITY`` to retrieve queue affinity info. It can
  set up the per-queue context efficiently, such as bind affine CPUs with IO
  pthread and try to allocate buffers in IO thread context.

- ``UBLK_CMD_GET_DEV_INFO``

  For retrieving device info via ``ublksrv_ctrl_dev_info``. It is the server's
  responsibility to save IO target specific info in userspace.

- ``UBLK_CMD_GET_DEV_INFO2``
  Same purpose with ``UBLK_CMD_GET_DEV_INFO``, but ublk server has to
  provide path of the char device of ``/dev/ublkc*`` for kernel to run
  permission check, and this command is added for supporting unprivileged
  ublk device, and introduced with ``UBLK_F_UNPRIVILEGED_DEV`` together.
  Only the user owning the requested device can retrieve the device info.

  How to deal with userspace/kernel compatibility:

  1) if kernel is capable of handling ``UBLK_F_UNPRIVILEGED_DEV``

    If ublk server supports ``UBLK_F_UNPRIVILEGED_DEV``:

    ublk server should send ``UBLK_CMD_GET_DEV_INFO2``, given anytime
    unprivileged application needs to query devices the current user owns,
    when the application has no idea if ``UBLK_F_UNPRIVILEGED_DEV`` is set
    given the capability info is stateless, and application should always
    retrieve it via ``UBLK_CMD_GET_DEV_INFO2``

    If ublk server doesn't support ``UBLK_F_UNPRIVILEGED_DEV``:

    ``UBLK_CMD_GET_DEV_INFO`` is always sent to kernel, and the feature of
    UBLK_F_UNPRIVILEGED_DEV isn't available for user

  2) if kernel isn't capable of handling ``UBLK_F_UNPRIVILEGED_DEV``

    If ublk server supports ``UBLK_F_UNPRIVILEGED_DEV``:

    ``UBLK_CMD_GET_DEV_INFO2`` is tried first, and will be failed, then
    ``UBLK_CMD_GET_DEV_INFO`` needs to be retried given
    ``UBLK_F_UNPRIVILEGED_DEV`` can't be set

    If ublk server doesn't support ``UBLK_F_UNPRIVILEGED_DEV``:

    ``UBLK_CMD_GET_DEV_INFO`` is always sent to kernel, and the feature of
    ``UBLK_F_UNPRIVILEGED_DEV`` isn't available for user

- ``UBLK_CMD_START_USER_RECOVERY``

  This command is valid if ``UBLK_F_USER_RECOVERY`` feature is enabled. This
  command is accepted after the old process has exited, ublk device is quiesced
  and ``/dev/ublkc*`` is released. User should send this command before he starts
  a new process which re-opens ``/dev/ublkc*``. When this command returns, the
  ublk device is ready for the new process.

- ``UBLK_CMD_END_USER_RECOVERY``

  This command is valid if ``UBLK_F_USER_RECOVERY`` feature is enabled. This
  command is accepted after ublk device is quiesced and a new process has
  opened ``/dev/ublkc*`` and get all ublk queues be ready. When this command
  returns, ublk device is unquiesced and new I/O requests are passed to the
  new process.

- user recovery feature description

  Two new features are added for user recovery: ``UBLK_F_USER_RECOVERY`` and
  ``UBLK_F_USER_RECOVERY_REISSUE``.

  With ``UBLK_F_USER_RECOVERY`` set, after one ubq_daemon(ublk server's io
  handler) is dying, ublk does not delete ``/dev/ublkb*`` during the whole
  recovery stage and ublk device ID is kept. It is ublk server's
  responsibility to recover the device context by its own knowledge.
  Requests which have not been issued to userspace are requeued. Requests
  which have been issued to userspace are aborted.

  With ``UBLK_F_USER_RECOVERY_REISSUE`` set, after one ubq_daemon(ublk
  server's io handler) is dying, contrary to ``UBLK_F_USER_RECOVERY``,
  requests which have been issued to userspace are requeued and will be
  re-issued to the new process after handling ``UBLK_CMD_END_USER_RECOVERY``.
  ``UBLK_F_USER_RECOVERY_REISSUE`` is designed for backends who tolerate
  double-write since the driver may issue the same I/O request twice. It
  might be useful to a read-only FS or a VM backend.

Unprivileged ublk device is supported by passing ``UBLK_F_UNPRIVILEGED_DEV``.
Once the flag is set, all control commands can be sent by unprivileged
user. Except for command of ``UBLK_CMD_ADD_DEV``, permission check on
the specified char device(``/dev/ublkc*``) is done for all other control
commands by ublk driver, for doing that, path of the char device has to
be provided in these commands' payload from ublk server. With this way,
ublk device becomes container-ware, and device created in one container
can be controlled/accessed just inside this container.

Data plane
----------

ublk server needs to create per-queue IO pthread & io_uring for handling IO
commands via io_uring passthrough. The per-queue IO pthread
focuses on IO handling and shouldn't handle any control & management
tasks.

The's IO is assigned by a unique tag, which is 1:1 mapping with IO
request of ``/dev/ublkb*``.

UAPI structure of ``ublksrv_io_desc`` is defined for describing each IO from
the driver. A fixed mmaped area (array) on ``/dev/ublkc*`` is provided for
exporting IO info to the server; such as IO offset, length, OP/flags and
buffer address. Each ``ublksrv_io_desc`` instance can be indexed via queue id
and IO tag directly.

The following IO commands are communicated via io_uring passthrough command,
and each command is only for forwarding the IO and committing the result
with specified IO tag in the command data:

- ``UBLK_IO_FETCH_REQ``

  Sent from the server IO pthread for fetching future incoming IO requests
  destined to ``/dev/ublkb*``. This command is sent only once from the server
  IO pthread for ublk driver to setup IO forward environment.

- ``UBLK_IO_COMMIT_AND_FETCH_REQ``

  When an IO request is destined to ``/dev/ublkb*``, the driver stores
  the IO's ``ublksrv_io_desc`` to the specified mapped area; then the
  previous received IO command of this IO tag (either ``UBLK_IO_FETCH_REQ``
  or ``UBLK_IO_COMMIT_AND_FETCH_REQ)`` is completed, so the server gets
  the IO notification via io_uring.

  After the server handles the IO, its result is committed back to the
  driver by sending ``UBLK_IO_COMMIT_AND_FETCH_REQ`` back. Once ublkdrv
  received this command, it parses the result and complete the request to
  ``/dev/ublkb*``. In the meantime setup environment for fetching future
  requests with the same IO tag. That is, ``UBLK_IO_COMMIT_AND_FETCH_REQ``
  is reused for both fetching request and committing back IO result.

- ``UBLK_IO_NEED_GET_DATA``

  With ``UBLK_F_NEED_GET_DATA`` enabled, the WRITE request will be firstly
  issued to ublk server without data copy. Then, IO backend of ublk server
  receives the request and it can allocate data buffer and embed its addr
  inside this new io command. After the kernel driver gets the command,
  data copy is done from request pages to this backend's buffer. Finally,
  backend receives the request again with data to be written and it can
  truly handle the request.

  ``UBLK_IO_NEED_GET_DATA`` adds one additional round-trip and one
  io_uring_enter() syscall. Any user thinks that it may lower performance
  should not enable UBLK_F_NEED_GET_DATA. ublk server pre-allocates IO
  buffer for each IO by default. Any new project should try to use this
  buffer to communicate with ublk driver. However, existing project may
  break or not able to consume the new buffer interface; that's why this
  command is added for backwards compatibility so that existing projects
  can still consume existing buffers.

- data copy between ublk server IO buffer and ublk block IO request

  The driver needs to copy the block IO request pages into the server buffer
  (pages) first for WRITE before notifying the server of the coming IO, so
  that the server can handle WRITE request.

  When the server handles READ request and sends
  ``UBLK_IO_COMMIT_AND_FETCH_REQ`` to the server, ublkdrv needs to copy
  the server buffer (pages) read to the IO request pages.

- ``UBLK_IO_XPIPE_ADD_BUF``

  Used for implementing zero copy feature.

  It has to be sent via IORING_OP_XPIPE_ADD_BUF, and this command provides
  buffer to xpipe, so io_uring OPs can use this buffer. From ublk viewpoint,
  the provides buffer is read-only if the IO request isn't completed.

Zero copy
=========

What is zero copy?
------------------

When application submits IO to ``/dev/ublkb*``, userspace buffer(direct io)
or page cache buffer(buffered io) or kernel buffer(meta io often) is used
for submitting data to ublk driver, and all kinds of these buffers are
represented by bio/bvecs(ublk request buffer) finally. Before supporting
zero copy, data in these buffers has to be copied to ublk server userspace
buffer before handling WRITE IO, or after handing READ IO, so that ublk
server can handle IO for ``/dev/ublkb*`` with the copied data.

The extra copy between ublk request buffer and ublk server userspace buffer
not only increases CPU utilization(such as pinning pages, copy data), but
also consumes memory bandwidth, and the cost could be very big when IO size
is big. It is observed that ublk-null IOPS may be increased to ~5X if the
extra copy can be avoided.

So zero copy is very important for supporting high performance block device
in userspace.

Technical requirements
----------------------

- ublk request buffer use

ublk request buffer is represented by bio/bvec, which is immutable, so do
not try to change bvec via buffer reference; data can be read from or
written to the buffer according to buffer direction, but bvec can't be
changed

- buffer lifetime

Ublk server borrows ublk request buffer for handling ublk IO, ublk request
buffer reference is used. Reference can't outlive the referent buffer. That
means all request buffer references have to be released by ublk server
before ublk driver completes this request, when request buffer ownership
is transferred to upper layer(FS, application, ...).

Also after ublk request is completed, any page belonging to this ublk
request can not be written or read any more from ublk server since it is
one block device from kernel viewpoint.

- buffer direction

For ublk WRITE request, ublk request buffer should only be accessed as data
source, and the buffer can't be written by ublk server

For ublk READ request, ublk request buffer should only be accessed as data
destination, and the buffer can't be read by ublk server, otherwise kernel
data is leaked to ublk server, which can be unprivileged application.

- arbitrary size sub-buffer needs to be retrieved from ublk server

ublk is one generic framework for implementing block device in userspace,
and typical requirements include logical volume manager(mirror, stripped, ...),
distributed network storage, compressed target, ...

ublk server needs to retrieve arbitrary size sub-buffer of ublk request, and
ublk server needs to submit IOs with these sub-buffer(s). That also means
arbitrary size sub-buffer(s) can be used to submit IO multiple times.

Any sub-buffer is actually one reference of ublk request buffer, which
ownership can't be transferred to upper layer if any reference is held
by ublk server.

Why splice isn't good for ublk zero copy
---------------------------------------

- spliced page from ->splice_read() can't be written

ublk READ request can't be handled because spliced page can't be written to, and
extending splice for ublk zero copy isn't one good solution [#splice_extend]_

- it is very hard to meet above requirements  wrt. request buffer lifetime

splice/pipe focuses on page reference lifetime, but ublk zero copy pays more
attention to ublk request buffer lifetime. If is very inefficient to respect
request buffer lifetime by using all pipe buffer's ->release() which requires
all pipe buffers and pipe to be kept when ublk server handles IO. That means
one single dedicated ``pipe_inode_info`` has to be allocated runtime for each
provided buffer, and the pipe needs to be populated with pages in ublk request
buffer.


io_uring xpipe based zero copy
------------------------------

Add new io command to produce IO request buffer for io_uring OPs, and same buffer
can only be added to xpipe once because the key is same.

io_uring OPs consume the buffer.

After no one use the buffer, either it is removed from xpipe by another uring
command, or use IORING_URING_CMD_XPIPE_AUTO option to remove it automatically.


References
==========

.. [#userspace] https://github.com/ming1/ubdsrv

.. [#userspace_lib] https://github.com/ming1/ubdsrv/tree/master/lib

.. [#userspace_nbdublk] https://gitlab.com/rwmjones/libnbd/-/tree/nbdublk

.. [#userspace_readme] https://github.com/ming1/ubdsrv/blob/master/README

.. [#stefan] https://lore.kernel.org/linux-block/YoOr6jBfgVm8GvWg@stefanha-x1.localdomain/

.. [#splice_extend] https://lore.kernel.org/linux-block/CAHk-=wgJsi7t7YYpuo6ewXGnHz2nmj67iWR6KPGoz5TBu34mWQ@mail.gmail.com/
