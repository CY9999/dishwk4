#@load base/frameworks/sumstats
event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("response_all",[$host=c$id$orig_h],[$num=1]);
	if(code==404)
	{
		SumStats::observe("response_404",[$host=c$id$orig_h],[$num=1]);
		SumStats::observe("response_404_unique",[$host=c$id$orig_h],[$str=c$http$uri]);
	}
}
event zeek_init()
{
	local r1=SumStats::Reducer($stream="reponse_all",$apply=set(SumStats::SUM));
	local r2=SumStats::Reducer($stream="reponse_404",$apply=set(SumStats::SUM));
	local r3=SumStats::Reducer($stream="reponse_404_unique",$apply=set(SumStats::SUM));
	SumStats::create([$name="http.lookup",
					 $epoch=10min,
					 $reducers=set(r1,r2,r3),
					 $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result)=
					 {
						local a1=result["reponse_all"];
						local a2=result["reponse_404"];
						local a3=result["reponse_404_unique"];
						if(a2$sum>2)
						{
							if(a2$sum/a1$sum>0.2)
							{
								if(a3$unique/a2$sum>0.5)
								{
									print fmt("%s is a scanner with %.0f scan attemps on %d urls",key$host,a2$sum,a3$unique);
								}
							}
						}
					 }]);
}
