event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("resp",
		SumStats::Key($host=c$id$orig_h), 
		SumStats::Observation($num=1));
	if(code == 404){
		SumStats::observe("404_resp",
			SumStats::Key($host=c$id$orig_h), 
			SumStats::Observation($num=1));
		SumStats::observe("unique_404_resp",
			SumStats::Key($host=c$id$orig_h), 
			SumStats::Observation($str=c$http$uri));
	}
}

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="resp",
		$apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="404_resp",
		$apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="unique_404_resp",
		$apply=set(SumStats::UNIQUE));
	SumStats::create([$name = "detect the attacker",
		$epoch = 10min,
		$reducers = set(r1, r2, r3),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
		{
			local c1 = result["resp"];
			local c2 = result["404_resp"];
			local c3 = result["unique_404_resp"];
			if(c2$sum > 2 && 1.0 * c2$sum / c1$sum > 0.2 && 1.0 * c3$unique / c2$sum > 0.5)
			{
				print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, c2$sum, c3$unique);	
			}
		}]);
}