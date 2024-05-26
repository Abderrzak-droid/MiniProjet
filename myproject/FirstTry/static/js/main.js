(function($) {
    "use strict";

    var fullHeight = function() {
        $('.js-fullheight').css('height', $(window).height());
        $(window).resize(function(){
            $('.js-fullheight').css('height', $(window).height());
        });
    };

    fullHeight();

    $('#sidebarCollapse').on('click', function () {
        $('#sidebar').toggleClass('active');
    });
})(jQuery);

document.addEventListener('DOMContentLoaded', function () {
	fetch('vulnerability_data')
		.then(response => {
			if (!response.ok) {
				throw new Error('Network response was not ok');
			}
			return response.json();
		})
		.then(data => {
			const formattedData = [
				{ name: 'Low', quantity: data.low },
				{ name: 'Medium', quantity: data.medium },
				{ name: 'High', quantity: data.high },
			];
			console.log('Formatted Data:', formattedData); // Debug: Check the data
			drawPieChart(formattedData);
		})
		.catch(error => {
			console.error('There has been a problem with your fetch operation:', error);
		});

	function drawPieChart(data) {
		var pieGenerator = d3.pie()
			.value(function (d) { return d.quantity; })
			.sort(null); // No sorting to maintain input order

		var arcGenerator = d3.arc()
			.innerRadius(20)
			.outerRadius(100);

		var arcData = pieGenerator(data);

		var svg = d3.select('g');

		svg.selectAll('path')
			.data(arcData)
			.join('path')
			.attr('d', arcGenerator)
			.attr('fill', function (d) {
				console.log('Data for fill:', d.data); // Debug: Check the data for fill
				if (d.data.name === 'Low') return 'green';
				if (d.data.name === 'Medium') return 'blue';
				if (d.data.name === 'High') return 'red';
				return '#ccc';
			})
			.attr('stroke', 'white')
			.attr('stroke-width', '2px')
			.style('fill', (d, i) => {
				return getRandomColor(i); 
			});

		svg.selectAll('text')
			.data(arcData)
			.join('text')
			.each(function (d) {
				var centroid = arcGenerator.centroid(d);
				d3.select(this)
					.attr('x', centroid[0])
					.attr('y', centroid[1])
					.attr('dy', '0.33em')
					.attr('text-anchor', 'middle')
					.text(d.data.name)
					.style('fill', 'white')  // Ensure text is visible
					.style('font-size', '10px');
			});

		drawLegend(data);
	}

	function drawLegend(data) {
		var legend = d3.select('.legend');

		legend.selectAll('div')
			.data(data)
			.join('div')
			.each(function (d) {
				var color;
				if (d.name === 'Low') color = 'gray';
				if (d.name === 'Medium') color = 'navy';
				if (d.name === 'High') color = 'red';

				d3.select(this)
					.html('<span style="background-color:' + color + '"></span>' + d.name + ': ' + d.quantity);
			});
	}
});

function getRandomColor(i) {
	const colors = ['gray', 'navy', 'red'];
	return colors[i % colors.length];
}