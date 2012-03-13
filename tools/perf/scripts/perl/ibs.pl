#
# ibs.pl - perf script for AMD Instruction Based Sampling
#
# Copyright (C) 2011 Advanced Micro Devices, Inc., Robert Richter
#
# For licencing details see kernel-base/COPYING
#
# description: collect and display AMD IBS samples
# args: [ibs_op|ibs_fetch] [-c period]
#
# examples:
#
#  perf script ibs ibs_op <command>
#  perf script ibs ibs_fetch <command>
#  perf script record ibs ibs_op -c 500000 <command>
#  perf script report ibs
#  perf script record ibs ibs_op -c 500000 <command> | perf script report ibs
#

# Packed byte string args of process_event():
#
# $event:	union perf_event	util/event.h
# $attr:	struct perf_event_attr	linux/perf_event.h
# $sample:	struct perf_sample	util/event.h
# $raw_data:	perf_sample->raw_data	util/event.h

sub process_event
{
	my ($event, $attr, $sample, $raw_data) = @_;

	my ($type)		= (unpack("LSS", $event))[0];
	my ($sample_type)	= (unpack("LLQQQQQLLQQ", $attr))[4];
	my ($cpu, $raw_size)	= (unpack("QLLQQQQQLL", $sample))[8, 9];
	my ($caps, @ibs_data)	= unpack("LQ*", $raw_data);

	return if (!$raw_size);		# no raw data

	if (scalar(@ibs_data) ==  3) {
	        printf("IBS_FETCH sample on cpu%d\tIBS0: 0x%016x IBS1: 0x%016x IBS2:0x%016x\n",
		       $cpu, @ibs_data);
	} else {
	        printf("IBS_OP sample on cpu%d\t" .
		       "\t IBS0: 0x%016x IBS1: 0x%016x IBS2: 0x%016x\n" .
		       "\tIBS3: 0x%016x IBS4: 0x%016x IBS5: 0x%016x IBS6: 0x%016x\n",
		       cpu, @ibs_data);
	}
}
