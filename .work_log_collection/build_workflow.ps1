$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$taskOut='D:\Applications\loaderfilter_tool'
$taskWidth=1560; $taskHeight=660; $taskScale=3
$taskNodes=@(
 @{id='source';x=30;y=210;w=300;h=120;lines=@('WinMET Reports','Volumes 1-5')},
 @{id='discovery';x=430;y=210;w=300;h=120;lines=@('Report','Identification')},
 @{id='inventory';x=830;y=210;w=300;h=120;lines=@('Label Matching','and Candidate','Screening')},
 @{id='evidence';x=1230;y=210;w=300;h=120;lines=@('Behavioral Evidence','Extraction')},
 @{id='manifest';x=1230;y=470;w=300;h=120;lines=@('Selection Records','and Traceability')},
 @{id='qa';x=830;y=470;w=300;h=120;lines=@('Data Quality','Checks')},
 @{id='export';x=430;y=470;w=300;h=120;lines=@('Candidate Report','Export')},
 @{id='output';x=30;y=470;w=300;h=120;lines=@('Loader-Candidate','Reports','Input to Module 2')},
 @{id='metadata';x=830;y=20;w=300;h=110;lines=@('CAPE / AVClass Labels','Consensus Metadata','Loader Family List');small=$true}
)
$taskEdges=@(
 @{id='a';source='source';target='discovery';pts=@(@(330,270),@(430,270));exitX=1;exitY=0.5;entryX=0;entryY=0.5},
 @{id='b';source='discovery';target='inventory';pts=@(@(730,270),@(830,270));exitX=1;exitY=0.5;entryX=0;entryY=0.5},
 @{id='c';source='inventory';target='evidence';pts=@(@(1130,270),@(1230,270));exitX=1;exitY=0.5;entryX=0;entryY=0.5},
 @{id='d';source='evidence';target='manifest';pts=@(@(1380,330),@(1380,470));exitX=0.5;exitY=1;entryX=0.5;entryY=0},
 @{id='e';source='manifest';target='qa';pts=@(@(1230,530),@(1130,530));exitX=0;exitY=0.5;entryX=1;entryY=0.5},
 @{id='f';source='qa';target='export';pts=@(@(830,530),@(730,530));exitX=0;exitY=0.5;entryX=1;entryY=0.5},
 @{id='g';source='export';target='output';pts=@(@(430,530),@(330,530));exitX=0;exitY=0.5;entryX=1;entryY=0.5},
 @{id='h';source='metadata';target='inventory';pts=@(@(980,130),@(980,210));exitX=0.5;exitY=1;entryX=0.5;entryY=0},
 @{id='skip';source='inventory';target='manifest';pts=@(@(980,330),@(980,395),@(1300,395),@(1300,470));exitX=0.5;exitY=1;entryX=0.2333333;entryY=0;dashed=$true}
)
function Rounded-Path([single]$x,[single]$y,[single]$w,[single]$h,[single]$r) {
 $path=[System.Drawing.Drawing2D.GraphicsPath]::new()
 $d=2*$r
 $path.AddArc($x,$y,$d,$d,180,90); $path.AddArc($x+$w-$d,$y,$d,$d,270,90)
 $path.AddArc($x+$w-$d,$y+$h-$d,$d,$d,0,90); $path.AddArc($x,$y+$h-$d,$d,$d,90,90)
 $path.CloseFigure(); return $path
}
$taskBitmap=[System.Drawing.Bitmap]::new($taskWidth*$taskScale,$taskHeight*$taskScale)
$taskBitmap.SetResolution(300,300)
$g=[System.Drawing.Graphics]::FromImage($taskBitmap)
$g.Clear([System.Drawing.Color]::White)
$g.ScaleTransform($taskScale,$taskScale)
$g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$border=[System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(50,50,50),2)
$groupPen=[System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(125,125,125),1.7)
$groupPen.DashPattern=@(6,4)
$groupPath=Rounded-Path 405 165 1145 455 14
$g.DrawPath($groupPen,$groupPath)
$font=[System.Drawing.Font]::new('Arial',27,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Pixel)
$smallFont=[System.Drawing.Font]::new('Arial',22,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Pixel)
$groupFont=[System.Drawing.Font]::new('Arial',23,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Pixel)
$fmt=[System.Drawing.StringFormat]::new()
$fmt.Alignment=[System.Drawing.StringAlignment]::Center
$fmt.LineAlignment=[System.Drawing.StringAlignment]::Center
$g.DrawString('Loader Log Filtering',$groupFont,[System.Drawing.Brushes]::Black,[single]430,[single]175)
foreach($n in $taskNodes) {
 $path=Rounded-Path $n.x $n.y $n.w $n.h 15
 $g.FillPath([System.Drawing.Brushes]::White,$path); $g.DrawPath($border,$path); $path.Dispose()
 $f=if($n.small){$smallFont}else{$font}
 $lh=if($n.small){28}else{33}
 $middle=$n.y+$n.h/2
 for($i=0;$i -lt $n.lines.Count;$i++) {
  $cy=$middle+($i-($n.lines.Count-1)/2)*$lh
  $g.DrawString($n.lines[$i],$f,[System.Drawing.Brushes]::Black,[System.Drawing.RectangleF]::new($n.x+8,$cy-$lh/2,$n.w-16,$lh),$fmt)
 }
}
foreach($e in $taskEdges) {
 $pen=[System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(45,45,45),2.2)
 if($e.dashed){$pen.DashPattern=@(6,4)}
 $pen.CustomEndCap=[System.Drawing.Drawing2D.AdjustableArrowCap]::new(4.5,6,$true)
 [System.Drawing.PointF[]]$points=@($e.pts | ForEach-Object { [System.Drawing.PointF]::new($_[0],$_[1]) })
 $g.DrawLines($pen,$points);$pen.Dispose()
}
$g.DrawString("with`nevidence",$smallFont,[System.Drawing.Brushes]::Black,[System.Drawing.RectangleF]::new(1130,206,100,58),$fmt)
$g.DrawString('labels only',$smallFont,[System.Drawing.Brushes]::Black,[System.Drawing.RectangleF]::new(1060,355,170,34),$fmt)
$png=Join-Path $taskOut 'Module_1_Log_Collection_Thesis_Workflow.png'
$taskBitmap.Save($png,[System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose();$taskBitmap.Dispose();$font.Dispose();$smallFont.Dispose();$groupFont.Dispose();$border.Dispose();$groupPen.Dispose();$groupPath.Dispose();$fmt.Dispose()

function Esc([string]$s){[System.Security.SecurityElement]::Escape($s)}
$cells='<mxCell id="0"/><mxCell id="1" parent="0"/>'
$cells+='<mxCell id="tool" value="" style="rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#7D7D7D;strokeWidth=1.7;dashed=1;dashPattern=6 4;arcSize=4;" vertex="1" parent="1"><mxGeometry x="405" y="165" width="1145" height="455" as="geometry"/></mxCell>'
$cells+='<mxCell id="tool_label" value="Loader Log Filtering" style="text;html=1;align=left;verticalAlign=middle;whiteSpace=wrap;fontFamily=Arial;fontSize=23;fontStyle=1;" vertex="1" parent="1"><mxGeometry x="430" y="169" width="290" height="35" as="geometry"/></mxCell>'
foreach($n in $taskNodes){
 $fontSize=if($n.small){22}else{27}
 $label=Esc ($n.lines -join '<br>')
 $cells+='<mxCell id="'+$n.id+'" value="'+$label+'" style="rounded=1;whiteSpace=wrap;html=1;align=center;verticalAlign=middle;fontFamily=Arial;fontSize='+$fontSize+';fontColor=#000000;fillColor=#FFFFFF;strokeColor=#323232;strokeWidth=2;arcSize=12;spacing=7;" vertex="1" parent="1"><mxGeometry x="'+$n.x+'" y="'+$n.y+'" width="'+$n.w+'" height="'+$n.h+'" as="geometry"/></mxCell>'
}
foreach($e in $taskEdges){
 $dashed=if($e.dashed){'dashed=1;dashPattern=6 4;'}else{''}
 $style='edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#2D2D2D;strokeWidth=2.2;exitX='+$e.exitX+';exitY='+$e.exitY+';exitDx=0;exitDy=0;entryX='+$e.entryX+';entryY='+$e.entryY+';entryDx=0;entryDy=0;'+$dashed
 $waypoints=''
 if($e.pts.Count -gt 2){$waypoints='<Array as="points">';for($i=1;$i -lt $e.pts.Count-1;$i++){$waypoints+='<mxPoint x="'+$e.pts[$i][0]+'" y="'+$e.pts[$i][1]+'"/>'};$waypoints+='</Array>'}
 $cells+='<mxCell id="edge_'+$e.id+'" value="" style="'+$style+'" edge="1" parent="1" source="'+$e.source+'" target="'+$e.target+'"><mxGeometry relative="1" as="geometry">'+$waypoints+'</mxGeometry></mxCell>'
}
$cells+='<mxCell id="evidence_label" value="with&lt;br&gt;evidence" style="text;html=1;align=center;verticalAlign=middle;fontFamily=Arial;fontSize=22;" vertex="1" parent="1"><mxGeometry x="1130" y="206" width="100" height="58" as="geometry"/></mxCell>'
$cells+='<mxCell id="labels_label" value="labels only" style="text;html=1;align=center;verticalAlign=middle;fontFamily=Arial;fontSize=22;" vertex="1" parent="1"><mxGeometry x="1060" y="355" width="170" height="34" as="geometry"/></mxCell>'
$drawio='<?xml version="1.0" encoding="UTF-8"?><mxfile host="app.diagrams.net"><diagram id="module1" name="Module 1 Log Collection"><mxGraphModel dx="1560" dy="660" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" pageScale="1" pageWidth="1560" pageHeight="660" math="0" shadow="0"><root>'+$cells+'</root></mxGraphModel></diagram></mxfile>'
[xml]$checked=$drawio
$drawioPath=Join-Path $taskOut 'Module_1_Log_Collection_Thesis_Workflow.drawio'
[System.IO.File]::WriteAllText($drawioPath,$drawio,[System.Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath $png,$drawioPath | Select-Object FullName,Length
